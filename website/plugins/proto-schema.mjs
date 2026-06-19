// proto-schema reads the compiler's descriptor (gen/descriptor.binpb, emitted by
// `buf build`) and exposes the schema the docs need: enum values + their proto
// comments (the canonical table descriptions), the vocabulary axes (the
// (ramp.v1.vocab)/(ramp.v1.vocab_enum) custom options), and the set of resolvable
// symbols for autolinking.
//
// It reads the descriptor as *data* via @bufbuild/protobuf — it is NOT the generated
// gen/ts runtime (which lacks protovalidate and strips comments), so that library's
// incompleteness never enters the docs. Comments come from SourceCodeInfo; custom
// options via the registry's getExtension (the vocab extensions are defined in the
// descriptor itself). No regex on .proto source, no hand-rolled wire decoding.
import { fromBinary, createFileRegistry, getExtension } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DESCRIPTOR = new URL('../../gen/descriptor.binpb', import.meta.url);

// Field numbers from google/protobuf/descriptor.proto — used to address elements in
// SourceCodeInfo.location[].path (how protobuf attaches comments to elements).
const F_MESSAGE = 4, F_ENUM = 5; // in FileDescriptorProto
const M_NESTED = 3, M_ENUM = 4;  // in DescriptorProto
const E_VALUE = 2;               // in EnumDescriptorProto

// Which proto element carries each docs vocabulary axis. The axis ids match what the
// :::proto-vocab directive references.
const VOCAB_AXES = {
  function: { enum: 'RestrictionKind', value: 'RESTRICTION_KIND_FUNCTION' },
  geography: { enum: 'RestrictionKind', value: 'RESTRICTION_KIND_GEOGRAPHY' },
  'user-type': { enum: 'RestrictionKind', value: 'RESTRICTION_KIND_USER_TYPE' },
  'pricing-unit': { message: 'Pricing', field: 'unit' },
  'quota-metric': { message: 'Quota', field: 'metric' },
};

let cached;

export function loadSchema() {
  if (cached) return cached;
  const fds = fromBinary(FileDescriptorSetSchema, readFileSync(fileURLToPath(DESCRIPTOR)));

  /** enum name -> [{ value, number, doc }] (value is the short form, doc from proto comment) */
  const enums = {};
  /** symbol -> { kind } : messages, Message.field (+ jsonName), enums, enum values (full+short), services, Service.Method */
  const symbols = {};

  for (const file of fds.file) {
    const commentAt = new Map();
    for (const loc of file.sourceCodeInfo?.location ?? []) {
      const c = (loc.leadingComments || loc.trailingComments || '').trim();
      if (c) commentAt.set(loc.path.join(','), c);
    }

    const addEnum = (e, pathPrefix) => {
      symbols[e.name] = { kind: 'enum', type: e.name };
      enums[e.name] = e.value.map((v, vi) => {
        symbols[v.name] = { kind: 'enum_value', type: e.name };
        const short = stripEnumPrefix(e.name, v.name);
        if (short !== v.name) symbols[short] = { kind: 'enum_value', type: e.name };
        return {
          value: short,
          full: v.name,
          number: v.number,
          doc: commentAt.get([...pathPrefix, E_VALUE, vi].join(',')) ?? '',
        };
      });
    };

    const walkMessage = (m, pathPrefix) => {
      symbols[m.name] = { kind: 'message', type: m.name };
      for (const f of m.field) {
        symbols[`${m.name}.${f.name}`] = { kind: 'field', type: m.name };
        if (f.jsonName && f.jsonName !== f.name) symbols[`${m.name}.${f.jsonName}`] = { kind: 'field', type: m.name };
      }
      m.enumType.forEach((e, ei) => addEnum(e, [...pathPrefix, M_ENUM, ei]));
      m.nestedType.forEach((n, ni) => walkMessage(n, [...pathPrefix, M_NESTED, ni]));
    };

    file.enumType.forEach((e, ei) => addEnum(e, [F_ENUM, ei]));
    file.messageType.forEach((m, mi) => walkMessage(m, [F_MESSAGE, mi]));
    for (const s of file.service) {
      symbols[s.name] = { kind: 'service', type: s.name };
      for (const m of s.method) symbols[`${s.name}.${m.name}`] = { kind: 'method', type: s.name };
    }
  }

  // Vocabulary axes from the custom options, read via the registry (the vocab
  // extensions are declared in the descriptor, so getExtension decodes them).
  const reg = createFileRegistry(fds);
  const vEnumExt = reg.getExtension('ramp.v1.vocab_enum');
  const vFieldExt = reg.getExtension('ramp.v1.vocab');
  const vocab = {};
  for (const [axis, src] of Object.entries(VOCAB_AXES)) {
    let opts;
    if (src.enum) {
      opts = reg.getEnum(`ramp.v1.${src.enum}`)?.values.find((v) => v.name === src.value)?.proto.options;
      vocab[axis] = opts ? (getExtension(opts, vEnumExt) ?? []) : [];
    } else {
      opts = reg.getMessage(`ramp.v1.${src.message}`)?.fields.find((f) => f.name === src.field)?.proto.options;
      vocab[axis] = opts ? (getExtension(opts, vFieldExt) ?? []) : [];
    }
  }

  cached = { enums, symbols, vocab };
  return cached;
}

// stripEnumPrefix turns PRICING_MODEL_PER_UNIT -> PER_UNIT given enum PricingModel.
// (PascalCase -> SCREAMING_SNAKE prefix; string casing, not source parsing.)
function stripEnumPrefix(enumName, valueName) {
  const prefix = enumName.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase() + '_';
  return valueName.startsWith(prefix) ? valueName.slice(prefix.length) : valueName;
}
