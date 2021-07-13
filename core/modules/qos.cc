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
                                 struct MeteringField *f, uint8_t type) {
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
    f->attr_id =
        (type == FieldType)
            ? AddMetadataAttr(attr, f->size, Attribute::AccessMode::kRead)
            : AddMetadataAttr(attr, f->size, Attribute::AccessMode::kWrite);   
            
            std::cout<<"type="<<type<<"f->attr_id=" <<f->attr_id<<std::endl;

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
 //std::cout<<"Qos::Init called"<<std::endl;

  for (int i = 0; i < arg.fields_size(); i++) {
    const auto &field = arg.fields(i);
    CommandResponse err;
    fields_.emplace_back();
    struct MeteringField &f = fields_.back();
    f.pos = size_acc;
    err = AddFieldOne(field, &f, FieldType);
    if (err.error().code() != 0) {
      return err;
    }

    size_acc += f.size;
  }
  default_gate_ = DROP_GATE;
  total_key_size_ = align_ceil(size_acc, sizeof(uint64_t));
for (int i = 0; i < arg.values_size(); i++) {
    const auto &field = arg.values(i);
    CommandResponse err;
    values_.emplace_back();
    struct MeteringField &f = values_.back();
    f.pos = value_acc;
    err = AddFieldOne(field, &f, ValueType);
    if (err.error().code() != 0) {
      return err;
    }

    value_acc += f.size;
  }
  

  total_value_size_ = align_ceil(value_acc, sizeof(uint64_t));
  std::cout<<"Init values_-size"<<total_value_size_<<std::endl;
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
   bess::Packet *pkt = nullptr;
   int packeti=0;
   //std::cout<<"process batch ="<<this<<std::endl;

  int cnt = batch->cnt(); //std::cout<<"cnt="<<cnt<<std::endl;
  gate_idx_t Outgate[cnt];  
   struct QosData *val[cnt];

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

    /*  size_t len1 = reinterpret_cast<size_t> (total_key_size_/sizeof(uint8_t));

      char *c = (char *)(&keys[0]);
           for(size_t i=0;i<len1;i++)
          {
            std::cout<<"this="<<this<<"k=="<<static_cast<unsigned>(c[i]);
          }
          std::cout<<std::endl; */
    }
  }


  uint64_t hit_mask = table_.Find(keys, val, cnt);
  std::cout<<"hitmask="<<hit_mask<<std::endl;

  for (int i = 0; i < cnt; i++) {
    std::cout<<"LOOKUP-QER_KEY[0]="<<keys[i].u64_arr[0] << " ;1="<<keys[i].u64_arr[1] << " ;2="<<keys[i].u64_arr[2] <<" ;3=" <<keys[i].u64_arr[3] <<" ;4="<< keys[i].u64_arr[4] <<" ;5=" <<keys[i].u64_arr[5] <<" ;6=" <<keys[i].u64_arr[6] << " ;7="<<keys[i].u64_arr[7]<<std::endl;
  //   std::cout <<"EXTRACTED DATA FROM HASH="<<"qfi="<< static_cast<unsigned>(val[i]->qfi)<<"; ulstatus="<< static_cast<unsigned>(val[i]->ulStatus)<<std::endl;//"; dlstatus="<< static_cast<unsigned>(val[i]->dlStatus)<<"; cir="<< val[i]->cir <<"; pir="<< val[i]->pir<<"; cbs="<<val[i]->cbs << "; ebs="<<val[i]->ebs<<"; pbs="<< val[i]->pbs<<"; ulMbr="<< val[i]->ulMbr<<"; dlMbr="<<val[i]->dlMbr<<"; ulGbr="<< val[i]->ulGbr<<"; dlGbr="<< val[i]->dlGbr<<"m="<< val[i]->m<<"p="<< val[i]->p<<std::endl;
  //   std::cout <<"EXTRACTED DATA address="<<"val address="<< &(val[i])<<"qfi address="<< &(val[i]->qfi)<<"; ulstatus address="<< &(val[i]->ulStatus)<<std::endl;
  }

   for (int init = 0; init < cnt; init++) {
    /* if lookup was successful, then set values (if possible) */
    if (hit_mask & (1 << init)) {
      //val *e = (val*) result[init];
     // std::cout<< e->ctrid<<e->farid<<e->fseid<<e->pdrid<<e->qerid<<std::endl;

      pkt = batch->pkts()[packeti + init];
      size_t num_values_ = values_.size();  std::cout<<"Qos process-batch values_-size"<<values_.size()<<std::endl;
      for (size_t i = 0; i < num_values_; i++) {
        int value_size = values_[i].size;
        int value_pos = values_[i].pos;
        int value_off = values_[i].offset;
        int value_attr_id = values_[i].attr_id;
        uint8_t *data = pkt->head_data<uint8_t *>() + value_off;

      //  std::cout << "off: " << (int)value_off << ", sz: " << value_size <<",pos=" <<value_pos  << std::endl;
        if (value_attr_id < 0) { /* if it is offset-based */
          memcpy(data,
                 reinterpret_cast<uint8_t *>(val[init]) + value_pos,
                 value_size);    //  std::cout << "data="<<static_cast<unsigned>(char*)data))<<"val="<<static_cast<unsigned>(*((&val[init]) + value_pos))<<std::endl;
        } else { /* if it is attribute-based */
          typedef struct {
            uint8_t bytes[bess::metadata::kMetadataAttrMaxSize];
          } value_t;
          uint8_t *buf = (uint8_t *)(val[init])/*->keyv*/ + value_pos;
          std::cout<<"buf="<<static_cast<unsigned>(*buf)<<std::endl;

          std::cout << "Setting value " << std::hex
                     << *(reinterpret_cast<uint64_t *>(buf))
                     << " for attr_id: " << value_attr_id
                     << " of size: " << value_size
                     << " at value_pos: " << value_pos << std::endl;
 
    
          switch (value_size) {
            case 1:
              set_attr<uint8_t>(this, value_attr_id, pkt, *((uint8_t *)buf));
         //     uintptr_t *temp = get_attr(this, value_attr_id, pkt);
          //    std::cout<<"Qos:attr="<<static_cast<unsigned>(*temp)<<std::endl;
              break;
            case 2:
              set_attr<uint16_t>(this, value_attr_id, pkt,
                                 *((uint16_t *)((uint8_t *)buf)) );
          //     uint16_t *temp = get_attr(this, value_attr_id, pkt);
          //    std::cout<<"Qos:attr="<<(*temp)<<std::endl;
              break;
            case 4:
              set_attr<uint32_t>(this, value_attr_id, pkt,
                                 *((uint32_t *)((uint8_t *)buf)));
           //   uint32_t *temp = get_attr(this, value_attr_id, pkt);
           //   std::cout<<"Qos:attr="<<(*temp)<<std::endl;
              break;
            case 8:
              set_attr<uint64_t>(this, value_attr_id, pkt,
                                 *((uint64_t *)((uint8_t *)buf)));
          //    uint64_t *temp = get_attr(this, value_attr_id, pkt);
          //    std::cout<<"Qos:attr="<<(*temp)<<std::endl;
              break;
            default: {
              void *mt_ptr = _ptr_attr_with_offset<value_t>(
                  attr_offset(value_attr_id), pkt);
              bess::utils::CopySmall(mt_ptr, buf, value_size);
            } break;
          }
  
        }
      }
     // std::cout << "wild-key="<<result[init]->keyv.u64_arr[0]<<result[init]->keyv.u64_arr[1]<<result[init]->keyv.u64_arr[2]<<result[init]->keyv.u64_arr[3]<<result[init]->keyv.u64_arr[4]<<result[init]->keyv.u64_arr[5]<<result[init]->keyv.u64_arr[6]<<result[init]->keyv.u64_arr[7]<<std::endl;
      Outgate[init] = val[init]->ogate;
    } else
      Outgate[init] = default_gate;
  }
  
//////////////////////////

  //default_gate = ACCESS_ONCE(default_gate_);
 // int cnt = batch->cnt();
 // std::cout<<"ProcessBatch called"<<std::endl;
  for (int j = 0; j < cnt; j++) {
     
 //    if ((hit_mask & (1ULL << j)) == 0) {
  //      EmitPacket(ctx, batch->pkts()[j], default_gate);
  //      continue;
  //    }

#if 0
   // struct rte_meter_srtcm_params app_srtcm_params = {
     // .cir = data[j]->cir , .cbs = data[j]->cbs, .ebs = data[j]->ebs};
  int ret = rte_meter_srtcm_profile_config(&p, &app_srtcm_params);
  if (ret)
    std::cout<< "rte_meter_srtcm_profile_config failed"<<std::endl;  //return CommandFailure(ret, "rte_meter_srtcm_profile_config failed");
      
  ret = rte_meter_srtcm_config(&m,&p);
  if (ret) 
    std::cout<< "rte_meter_srtcm_config failed"<<std::endl; //return CommandFailure(ret, "rte_meter_srtcm_config failed");


//struct rte_meter_srtcm m;
  //struct rte_meter_srtcm_profile p;
    //std::cout <<"cir="<< data[j]->cir <<"cbs="<<data[j]->cbs << "ebs="<<data[j]->ebs<<std::endl;
    uint64_t time = rte_rdtsc();
    uint8_t color = rte_meter_srtcm_color_blind_check(
        /*((struct rte_meter_srtcm *)data[j]->m)*/ &m1, /*((rte_meter_srtcm_profile *)data[j]->p)*/&p1, time, batch->pkts()[j]->total_len());

    if (color != RTE_COLOR_GREEN)
      EmitPacket(ctx, batch->pkts()[j], default_gate);
    else {
      EmitPacket(ctx, batch->pkts()[j], Outgate[j]);
    }
#endif
//#else
    EmitPacket(ctx, batch->pkts()[j], Outgate[j]);
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
  return CommandSuccess();
}

template <typename T>
CommandResponse Qos::ExtractKeyMask(const T &arg, MeteringKey *key,
                                              QosData *val,MKey *l) {
  
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
                                      /*false*/true)) {
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


 for (size_t i = 0; i < fields_.size(); i++) {
    int field_size = fields_[i].size;
    int field_pos = fields_[i].pos;

    //uint64_t v = 0;
    uint64_t k = 0;

    bess::pb::FieldData fieldsdata = arg.fields(i);
    if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueInt) {
      if (!bess::utils::uint64_to_bin(&k, fieldsdata.value_int(), field_size,
                                      false)) {
        return CommandFailure(EINVAL, "idx %zu: not a correct %d-byte mask", i,
                              field_size);
      }
    } else if (fieldsdata.encoding_case() == bess::pb::FieldData::kValueBin) {
      bess::utils::Copy(reinterpret_cast<uint8_t *>(&k),
                        fieldsdata.value_bin().c_str(),
                        fieldsdata.value_bin().size());
    }
        
   
    memcpy(reinterpret_cast<uint8_t *>(l) + field_pos, &k, field_size);
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
 // std::cout<<"CommandAdd"<<std::endl;
  MeteringKey key={{0}} ;
 // struct rte_meter_srtcm m;
  //struct rte_meter_srtcm_profile p;
  MKey l;
  struct QosData data;
  data.ogate = gate;
    CommandResponse err =ExtractKeyMask(arg, &key,&data,&l);
    std::cout<<"Qer key 1="<<static_cast<unsigned>(l.key1)<<"qer key2="<<static_cast<unsigned>(l.key2)<<std::endl;
    
    //std::cout <<"COMMAND-ADD-INSERT qfi="<< static_cast<unsigned>(data.qfi)<<"; ulstatus="<< static_cast<unsigned>(data.ulStatus)<<"; dlstatus="<< static_cast<unsigned>(data.dlStatus)<<"; cir="<< data.cir <<"; pir="<< data.pir<<"; cbs="<<data.cbs << "; ebs="<<data.ebs<<"; pbs="<< data.pbs<<"; ulMbr="<< data.ulMbr<<"; dlMbr="<< data.dlMbr<<"; ulGbr="<< data.ulGbr<<"; dlGbr="<< data.dlGbr<<std::endl;
    if (err.error().code() != 0) {
    return err;
  }

  if (!is_valid_gate(gate)) {
    return CommandFailure(EINVAL, "Invalid gate: %hu", gate);
  }


#if 0
  //data.priority = priority;
  struct rte_meter_srtcm_params app_srtcm_params = {
      .cir = data.cir, .cbs = data.cbs, .ebs = data.ebs};
  int ret = rte_meter_srtcm_profile_config(&p, &app_srtcm_params);
  if (ret)
    return CommandFailure(ret, "Insert Failed - rte_meter_srtcm_profile_config failed");
      
  ret = rte_meter_srtcm_config(&m,&p);
  if (ret) {
    return CommandFailure(ret, "Insert Failed - rte_meter_srtcm_config failed");
  }
    m1 =m;
    p1=p;
    data.m = static_cast<void*>(&m);
    data.p = static_cast<void*>(&p);

#endif
std::cout<<"INSERT-QER_KEY[0]="<<key.u64_arr[0] << " ;1="<<key.u64_arr[1] << " ;2="<<key.u64_arr[2] <<" ;3=" <<key.u64_arr[3] <<" ;4="<< key.u64_arr[4] <<" ;5=" <<key.u64_arr[5] <<" ;6=" <<key.u64_arr[6] << " ;7="<<key.u64_arr[7]<<std::endl;
 std::cout << data.ogate<<std::endl;
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
