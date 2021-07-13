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

#ifndef BESS_MODULES_QOS_H_
#define BESS_MODULES_QOS_H_

#include "../module.h"

#include <rte_config.h>
#include <rte_hash_crc.h>

#include "../pb/module_msg.pb.h"
#include "../utils/metering.h"

using bess::utils::Metering;
using bess::utils::MeteringKey;

#define MAX_FIELDS 8
#define MAX_FIELD_SIZE 8
static_assert(MAX_FIELD_SIZE <= sizeof(uint64_t),
              "field cannot be larger than 8 bytes");

#define HASH_KEY_SIZE (MAX_FIELDS * MAX_FIELD_SIZE)

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error this code assumes little endian architecture (x86)
#endif

enum { FieldType = 0, ValueType };
/*
struct QosKey {
  uint64_t u64_arr[MAX_FIELDS];
};
*/
struct QosData {
  uint8_t qfi;
  uint8_t ulStatus;
  uint8_t dlStatus;
  uint32_t cir;
  uint32_t pir;
  uint32_t cbs;
  uint32_t ebs;
  uint32_t pbs;
  uint32_t ulMbr;
  uint32_t dlMbr;
  uint32_t ulGbr;
  uint32_t dlGbr;
  void *p;
  void *m;
  gate_idx_t ogate;
}__attribute__((packed));

struct MKey {
  uint8_t key1;
  uint8_t key2;
}__attribute__((packed));

//__uint64_t mask[8]={0xffffffffffffffff,0x00ffffffffffffff,0x0000ffffffffffff,0x000000ffffffffff,0x00000000ffffffff,0x0000000000ffffff,0x000000000000ffff,0x00000000000000ff,0x0000000000000000};

class Qos final : public Module {
 public:
  static const gate_idx_t kNumOGates = MAX_GATES;

  static const Commands cmds;

  Qos() : Module(), default_gate_(), total_key_size_(), fields_() {
    max_allowed_workers_ = Worker::kMaxWorkers; 
    size_t len = sizeof(mask)/sizeof(uint64_t);
    for(size_t i=0;i < len;i++)
         mask[i]=0;
  }

  CommandResponse Init(const bess::pb::QosArg &arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  CommandResponse CommandAdd(const bess::pb::QosCommandAddArg &arg);
  CommandResponse CommandDelete(const bess::pb::QosCommandDeleteArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandSetDefaultGate(
      const bess::pb::QosCommandSetDefaultGateArg &arg);
        template <typename T>
CommandResponse ExtractKeyMask(const T &arg, MeteringKey *key,
                                              QosData *val,MKey *l) ;
                                              template <typename T>
CommandResponse ExtractKey(const T &arg, MeteringKey *key) ;
  struct rte_meter_srtcm m1;
  struct rte_meter_srtcm_profile p1;
CommandResponse AddFieldOne(const bess::pb::Field &field,struct MeteringField *f, uint8_t type);
  gate_idx_t LookupEntry(const MeteringKey &key, gate_idx_t def_gate);
 private:



  //template <typename T>
  //CommandResponse ExtractKey(const T &arg, MeteringKey *key);

  int DelEntry(MeteringKey *key);
  int GetEntryCount();
  void Clear();
  gate_idx_t default_gate_;
  size_t total_key_size_; /* a multiple of sizeof(uint64_t) */
  size_t total_value_size_;
  std::vector<struct MeteringField> fields_;
  std::vector<struct MeteringField> values_;
  Metering<QosData> table_;
  uint64_t mask[8];
};

#endif  // BESS_MODULES_QOS_H
