// Copyright Intel Corp.
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
#include "qos.h"
#include "../utils/endian.h"
#include "../utils/format.h"
#include <rte_cycles.h>
#include <string>
#include <vector>

typedef enum { FIELD_TYPE = 0, VALUE_TYPE } Type;
using bess::metadata::Attribute;
#define metering_test 1
static inline int is_valid_gate(gate_idx_t gate) {
  return (gate < MAX_GATES || gate == DROP_GATE);
}

const Commands Qos::cmds = {
    {"add", "QosCommandAddArg", MODULE_CMD_FUNC(&Qos::CommandAdd),
     Command::THREAD_UNSAFE},
    {"delete", "QosCommandDeleteArg", MODULE_CMD_FUNC(&Qos::CommandDelete),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&Qos::CommandClear),
     Command::THREAD_UNSAFE},
    {"set_default_gate", "QosCommandSetDefaultGateArg",
     MODULE_CMD_FUNC(&Qos::CommandSetDefaultGate), Command::THREAD_SAFE}};

CommandResponse Qos::AddFieldOne(const bess::pb::Field &field,
                                 struct MeteringField *f) {
  f->size = field.num_bytes();

  if (f->size < 1 || f->size > MAX_FIELD_SIZE) {
    return CommandFailure(EINVAL, "'size' must be 1-%d", MAX_FIELD_SIZE);
  }

  if (field.position_case() == bess::pb::Field::kOffset) {
    f->attr_id = -1;
    f->offset = field.offset();
    if (f->offset < 0 || f->offset > 1024) {
      return CommandFailure(EINVAL, "too small 'offset'");
    }
  } else if (field.position_case() == bess::pb::Field::kAttrName) {
    const char *attr = field.attr_name().c_str();
    f->attr_id = AddMetadataAttr(attr, f->size, Attribute::AccessMode::kRead);
    if (f->attr_id < 0) {
      return CommandFailure(-f->attr_id, "add_metadata_attr() failed");
    }
  } else {
    return CommandFailure(EINVAL, "specify 'offset' or 'attr'");
  }

  return CommandSuccess();
}

CommandResponse Qos::Init(const bess::pb::QosArg &arg) {
  int size_acc = 0;

  for (int i = 0; i < arg.fields_size(); i++) {
    const auto &field = arg.fields(i);
    CommandResponse err;
    fields_.emplace_back();
    struct MeteringField &f = fields_.back();
    f.pos = size_acc;
    err = AddFieldOne(field, &f);
    if (err.error().code() != 0) {
      return err;
    }

    size_acc += f.size;
  }
  default_gate_ = DROP_GATE;
  total_key_size_ = align_ceil(size_acc, sizeof(uint64_t));
  table_.Init(total_key_size_);
#ifdef metering_test
  struct rte_meter_srtcm_params app_srtcm_params = {
      .cir = 1000000 * 46, .cbs = 2048, .ebs = 2048};
  int ret = rte_meter_srtcm_profile_config(&p, &app_srtcm_params);
  if (ret)
    return CommandFailure(ret, "rte_meter_srtcm_profile_config failed");
      
  ret = rte_meter_srtcm_config(&m,&p);
  if (ret) 
    return CommandFailure(ret, "rte_meter_srtcm_config failed");
#endif    
  return CommandSuccess();
}

void Qos::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t default_gate;
  default_gate = ACCESS_ONCE(default_gate_);
  int cnt = batch->cnt();

  for (int j = 0; j < cnt; j++) {
#ifdef metering_test
    uint64_t time = rte_rdtsc();
    uint8_t color = rte_meter_srtcm_color_blind_check(
        &m, &p, time, batch->pkts()[j]->total_len());
    if (color != RTE_COLOR_GREEN)
      EmitPacket(ctx, batch->pkts()[j], default_gate);
    else {
      EmitPacket(ctx, batch->pkts()[j], 0);
    }
#else
    EmitPacket(ctx, batch->pkts()[j], default_gate);
#endif    
  }
}
int Qos::GetEntryCount() {
  return table_.Count();
}

int Qos::DelEntry(__attribute__((unused)) MeteringKey *key) {
  // Delete(const MeteringKey &key)
  return 0;
}



template <typename T>
CommandResponse Qos::ExtractKey(const T &arg, MeteringKey *key) {
//  if ((size_t)arg.values_size() != fields_.size()) {
 //   return CommandFailure(EINVAL, "must specify %zu values", fields_.size());
 // } else 
  if ((size_t)arg.fields_size() != fields_.size()) {
    return CommandFailure(EINVAL, "must specify %zu masks", fields_.size());
  }

  memset(key, 0, sizeof(*key));
  //memset(val, 0, sizeof(*val));

  for (size_t i = 0; i < fields_.size(); i++) {
    int field_size = fields_[i].size;
    int field_pos = fields_[i].pos;

    uint64_t v = 0;
    //uint64_t m = 0;

  /*  bess::pb::FieldData valuedata = arg.values(i);
    if (valuedata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&v, valuedata.value_int(), field_size,
                                      true)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte value", i,
                              field_size);
      }
    } else 
    if (valuedata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&v),
                        valuedata.value_bin().c_str(),
                        valuedata.value_bin().size());
    }
*/

    bess::pb::FieldData fieldsdata = arg.fields(i);
    if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&m, fieldsdata.value_int(), field_size,
                                      true)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte mask", i,
                              field_size);
      }
    } else if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&m),
                        fieldsdata.value_bin().c_str(),
                        fieldsdata.value_bin().size());
    }

    if (v) {
      return CommandFailure(EINVAL,
                            "idx %zu: invalid pair of "
                            "value 0x%0*" PRIx64,/*
                            " and "
                            "mask 0x%0*" PRIx64,*/
                            i, field_size * 2, v);//, field_size * 2, m);
    }

    // Use memcpy, not utils::Copy, to workaround the false positive warning
    // in g++-8
    memcpy(reinterpret_cast<uint8_t *>(key) + field_pos, &v, field_size);
    //memcpy(reinterpret_cast<uint8_t *>(val) + field_pos, &m, field_size);
  }

  return CommandSuccess();
}

template <typename T>
CommandResponse Qos::ExtractKeyMask(const T &arg, MeteringKey *key,
                                              QosData *val) {
  if ((size_t)arg.values_size() != fields_.size()) {
    return CommandFailure(EINVAL, "must specify %zu values", fields_.size());
  } else if ((size_t)arg.fields_size() != fields_.size()) {
    return CommandFailure(EINVAL, "must specify %zu masks", fields_.size());
  }

  memset(key, 0, sizeof(*key));
  memset(val, 0, sizeof(*val));

  for (size_t i = 0; i < fields_.size(); i++) {
    int field_size = fields_[i].size;
    int field_pos = fields_[i].pos;

    uint64_t v = 0;
    uint64_t m = 0;

    bess::pb::FieldData valuedata = arg.values(i);
    if (valuedata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&v, valuedata.value_int(), field_size,
                                      true)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte value", i,
                              field_size);
      }
    } else if (valuedata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&v),
                        valuedata.value_bin().c_str(),
                        valuedata.value_bin().size());
    }

    bess::pb::FieldData fieldsdata = arg.fields(i);
    if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&m, fieldsdata.value_int(), field_size,
                                      true)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte mask", i,
                              field_size);
      }
    } else if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&m),
                        fieldsdata.value_bin().c_str(),
                        fieldsdata.value_bin().size());
    }

    if (v & ~m) {
      return CommandFailure(EINVAL,
                            "idx %zu: invalid pair of "
                            "value 0x%0*" PRIx64
                            " and "
                            "mask 0x%0*" PRIx64,
                            i, field_size * 2, v, field_size * 2, m);
    }

    // Use memcpy, not utils::Copy, to workaround the false positive warning
    // in g++-8
    memcpy(reinterpret_cast<uint8_t *>(key) + field_pos, &v, field_size);
    memcpy(reinterpret_cast<uint8_t *>(val) + field_pos, &m, field_size);
  }

  return CommandSuccess();
}


CommandResponse Qos::CommandAdd(const bess::pb::QosCommandAddArg &arg) {
  // to be done extract key & value..
  // table_.Add(const T &val, const MeteringKey &key)
gate_idx_t gate = arg.gate();
  
  MeteringKey key ;//= {0};
  QosData val ;//= {0};

  struct QosData data;
  
    CommandResponse err =ExtractKeyMask(arg, &key,&val);

 // CommandResponse err = ExtractKeyMask(arg, &key, &mask);
  if (err.error().code() != 0) {
    return err;
  }

  if (!is_valid_gate(gate)) {
    return CommandFailure(EINVAL, "Invalid gate: %hu", gate);
  }

  //data.priority = priority;
  data.ogate = gate;
  table_.Add(data, key);
  return CommandSuccess();
}

CommandResponse Qos::CommandDelete(const bess::pb::QosCommandDeleteArg &arg) {
  // to be implemented
  // extract key & call DelEntry
  MeteringKey key ;//= {0};
 // QosData val ;//= {0};
 // __attribute__((unused)) val;

 // struct QosData data;  
  CommandResponse err =ExtractKey(arg, &key);
  
  table_.Delete(key);
  return CommandSuccess();
}

CommandResponse Qos::CommandClear(__attribute__((unused))
                                  const bess::pb::EmptyArg &) {
  Qos::Clear();
  return CommandSuccess();
}

void Qos::Clear() {
  table_.Clear();
}

CommandResponse Qos::CommandSetDefaultGate(
    const bess::pb::QosCommandSetDefaultGateArg &arg) {
  default_gate_ = arg.gate();
  return CommandSuccess();
}

ADD_MODULE(Qos, "qos", "Multi-field classifier with a QOS")
