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
#define metering_test 0
static inline int is_valid_gate(gate_idx_t gate) {
  return (gate < MAX_GATES || gate == DROP_GATE);
}

const Commands Qos::cmds = {
    {"add", "QosCommandAddArg", MODULE_CMD_FUNC(&Qos::CommandAdd),
     Command::THREAD_SAFE},
    {"delete", "QosCommandDeleteArg", MODULE_CMD_FUNC(&Qos::CommandDelete),
     Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&Qos::CommandClear),
     Command::THREAD_SAFE},
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
  int value_acc=0;
 std::cout<<"Qos::Init called"<<std::endl;

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
  
for (int i = 0; i < arg.values_size(); i++) {
    const auto &field = arg.values(i);
    CommandResponse err;
    values_.emplace_back();
    struct MeteringField &f = values_.back();
    f.pos = value_acc;
    err = AddFieldOne(field, &f);
    if (err.error().code() != 0) {
      return err;
    }

    value_acc += f.size;
  }

  default_gate_ = DROP_GATE;
  total_key_size_ = align_ceil(size_acc, sizeof(uint64_t));
  total_value_size_ = align_ceil(value_acc, sizeof(uint64_t));
   // std::cout<<"size_acc="<<size_acc<<"total="<<total_key_size_<<std::endl;

    uint8_t* cs = (uint8_t*)&mask;
    for (int i = 0; i < size_acc; i++)
    {
        cs[i] = 0xff;       
    }
  //  std::cout <<"bo="<<static_cast<unsigned>(cs[0])<<"b1="<<static_cast<unsigned>(cs[1])<<"b2="<<static_cast<unsigned>(cs[2])<<"b3="<<static_cast<unsigned>(cs[3])<<"b4="<<static_cast<unsigned>(cs[4])<<"b5="<<static_cast<unsigned>(cs[5])<<"b6="<<static_cast<unsigned>(cs[6])<<"b7="<<static_cast<unsigned>(cs[7])<<std::endl;
 // std::cout <<"mask0="<<mask[0]<<";1="<<mask[1]<<";2="<<mask[2]<<";3="<<mask[3]<<";4="<<mask[4]<<";5="<<mask[5]<<";6="<<mask[6]<<";7="<<mask[7]<<std::endl;
  table_.Init(total_key_size_);
#ifdef oometering_test
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
   MeteringKey keys[bess::PacketBatch::kMaxBurst] __ymm_aligned;
   

  int cnt = batch->cnt(); //std::cout<<"cnt="<<cnt<<std::endl;
//  gate_idx_t Outgate[cnt];
struct QosData *data[cnt];

  // Initialize the padding with zero
  for (int i = 0; i < cnt; i++) {
    keys[i].u64_arr[0] = keys[i].u64_arr[1] = keys[i].u64_arr[2] = keys[i].u64_arr[3] = keys[i].u64_arr[4] = keys[i].u64_arr[5] = keys[i].u64_arr[6] = keys[i].u64_arr[7] =0;
  }
  //std::cout<<"before="<<cnt<<std::endl;
  default_gate = ACCESS_ONCE(default_gate_);
  for (const auto &field : fields_) {
  //  std::cout<<"after="<<cnt<<std::endl;
    int offset;
    int pos = field.pos;
    int attr_id = field.attr_id;

    if (attr_id < 0) {
      offset = field.offset;
    } else {
      offset = bess::Packet::mt_offset_to_databuf_offset(attr_offset(attr_id));
    }

    for (int j = 0; j < cnt; j++) {
      char *buf_addr = batch->pkts()[j]->buffer<char *>();

      /* for offset-based attrs we use relative offset */
      if (attr_id < 0) {
        buf_addr += batch->pkts()[j]->data_off();
      }

      char *key = reinterpret_cast<char *>(keys[j].u64_arr) + pos;

      *(reinterpret_cast<uint64_t *>(key)) =
          *(reinterpret_cast<uint64_t *>(buf_addr + offset));

         size_t len = reinterpret_cast<size_t> (total_key_size_/sizeof(uint64_t));
    //      std::cout<<"qer-key before mask="<<keys[j].u64_arr[0] << " ;1="<<keys[j].u64_arr[1] << " ;2="<<keys[j].u64_arr[2] <<" ;3=" <<keys[j].u64_arr[3] <<" ;4="<< keys[j].u64_arr[4] <<" ;5=" <<keys[j].u64_arr[5] <<" ;6=" <<keys[j].u64_arr[6] << " ;7="<<keys[j].u64_arr[7]<<std::endl;
         for(size_t i=0;i<len;i++)
          {
            keys[j].u64_arr[i]=keys[j].u64_arr[i] & mask[i];
          }
    }
  }

  uint64_t hit_mask = table_.Find(keys, data, cnt);
  std::cout<<"hitmask="<<hit_mask<<std::endl;

  for (int i = 0; i < cnt; i++) {
    std::cout<<"LOOKUP-QER_KEY[0]="<<keys[i].u64_arr[0] << " ;1="<<keys[i].u64_arr[1] << " ;2="<<keys[i].u64_arr[2] <<" ;3=" <<keys[i].u64_arr[3] <<" ;4="<< keys[i].u64_arr[4] <<" ;5=" <<keys[i].u64_arr[5] <<" ;6=" <<keys[i].u64_arr[6] << " ;7="<<keys[i].u64_arr[7]<<std::endl;
     std::cout <<"EXTRACTED DATA FROM HASH="<<"qfi="<< static_cast<unsigned>(data[i]->qfi)<<"; ulstatus="<< static_cast<unsigned>(data[i]->ulStatus)<<"; dlstatus="<< static_cast<unsigned>(data[i]->dlStatus)<<"; cir="<< data[i]->cir <<"; pir="<< data[i]->pir<<"; cbs="<<data[i]->cbs << "; ebs="<<data[i]->ebs<<"; pbs="<< data[i]->pbs<<"; ulMbr="<< data[i]->ulMbr<<"; dlMbr="<<data[i]->dlMbr<<"; ulGbr="<< data[i]->ulGbr<<"; dlGbr="<< data[i]->dlGbr<<std::endl;
  }
  
//////////////////////////
  struct rte_meter_srtcm m;
  struct rte_meter_srtcm_profile p;

 // gate_idx_t default_gate;
  default_gate = ACCESS_ONCE(default_gate_);
 // int cnt = batch->cnt();
 // std::cout<<"ProcessBatch called"<<std::endl;
  for (int j = 0; j < cnt; j++) {
     
     if ((hit_mask & (1ULL << j)) == 0) {
        EmitPacket(ctx, batch->pkts()[j], default_gate);
        continue;
      }

    struct rte_meter_srtcm_params app_srtcm_params = {
      .cir = data[j]->cir , .cbs = data[j]->cbs, .ebs = data[j]->ebs};

  std::cout <<"cir="<< data[j]->cir <<"cbs="<<data[j]->cbs << "ebs="<<data[j]->ebs<<std::endl;

  int ret = rte_meter_srtcm_profile_config(&p, &app_srtcm_params);
  if (ret)
    std::cout<< "rte_meter_srtcm_profile_config failed"<<std::endl;  //return CommandFailure(ret, "rte_meter_srtcm_profile_config failed");
      
  ret = rte_meter_srtcm_config(&m,&p);
  if (ret) 
    std::cout<< "rte_meter_srtcm_config failed"<<std::endl; //return CommandFailure(ret, "rte_meter_srtcm_config failed");
//#ifdef metering_test
    uint64_t time = rte_rdtsc();
    uint8_t color = rte_meter_srtcm_color_blind_check(
        &m, &p, time, batch->pkts()[j]->total_len());

    if (color != RTE_COLOR_GREEN)
      EmitPacket(ctx, batch->pkts()[j], default_gate);
    else {
      EmitPacket(ctx, batch->pkts()[j], 0);
    }

//#else
  //  EmitPacket(ctx, batch->pkts()[j], default_gate);
//#endif    
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
    uint64_t m = 0;

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
  
  if ((size_t)arg.fields_size() != fields_.size()) {
    return CommandFailure(EINVAL, "must specify %zu masks", fields_.size());
  }

  memset(key, 0, sizeof(*key));
  memset(val, 0, sizeof(*val));
  
  for (size_t i = 0; i < fields_.size(); i++) {
    int field_size = fields_[i].size;
    int field_pos = fields_[i].pos;

    //uint64_t v = 0;
    uint64_t k = 0;

    bess::pb::FieldData fieldsdata = arg.fields(i);
    if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&k, fieldsdata.value_int(), field_size,
                                      true)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte mask", i,
                              field_size);
      }
    } else if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&k),
                        fieldsdata.value_bin().c_str(),
                        fieldsdata.value_bin().size());
    }
        
   
    memcpy(reinterpret_cast<uint8_t *>(key) + field_pos, &k, field_size);
   }

    
   for (size_t i = 0; i < values_.size(); i++) {

    // arg.values(i);
    int val_size = values_[i].size;
    int val_pos = values_[i].pos;

    uint64_t v = 0;
    //uint64_t m = 0;

    bess::pb::FieldData valuedata = arg.values(i);
    if (valuedata.encoding_case() == bess::pb::FieldData::kValueInt) { 
      if (!bess::utils::uint64_to_bin(&v, valuedata.value_int(), val_size,
                                      false)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte value", i,
                              val_size);
      }
    } else if (valuedata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&v),
                        valuedata.value_bin().c_str(),
                        valuedata.value_bin().size());
    }

      
    memcpy(reinterpret_cast<uint8_t *>(val) + val_pos, &v, val_size);
    
  
   }
  return CommandSuccess();
}


CommandResponse Qos::CommandAdd(const bess::pb::QosCommandAddArg &arg) {
  // to be done extract key & value..
  // table_.Add(const T &val, const MeteringKey &key)
gate_idx_t gate = arg.gate();
  std::cout<<"CommandAdd"<<std::endl;
  MeteringKey key={{0}} ;
 

  struct QosData data;
  data.ogate = gate;
    CommandResponse err =ExtractKeyMask(arg, &key,&data);
    
    std::cout <<"COMMAND-ADD-INSERT qfi="<< static_cast<unsigned>(data.qfi)<<"; ulstatus="<< static_cast<unsigned>(data.ulStatus)<<"; dlstatus="<< static_cast<unsigned>(data.dlStatus)<<"; cir="<< data.cir <<"; pir="<< data.pir<<"; cbs="<<data.cbs << "; ebs="<<data.ebs<<"; pbs="<< data.pbs<<"; ulMbr="<< data.ulMbr<<"; dlMbr="<< data.dlMbr<<"; ulGbr="<< data.ulGbr<<"; dlGbr="<< data.dlGbr<<std::endl;
    if (err.error().code() != 0) {
    return err;
  }

  if (!is_valid_gate(gate)) {
    return CommandFailure(EINVAL, "Invalid gate: %hu", gate);
  }

  //data.priority = priority;
 // data.ogate = gate;
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
