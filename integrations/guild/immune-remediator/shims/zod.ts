/**
 * LOCAL SHIM for `zod` (type-check + local-run only). Guild's runtime provides real Zod 4.3.x;
 * this is the minimal builder surface agent.ts uses. `_output` carries the inferred type.
 */

type Flatten<T> = { [K in keyof T as undefined extends T[K] ? never : K]: T[K] } & {
  [K in keyof T as undefined extends T[K] ? K : never]?: T[K]
}

export interface ZodType<O = unknown> {
  readonly _output: O
  readonly kind: string
  optional(): ZodType<O | undefined>
  nullable(): ZodType<O | null>
  describe(description: string): this
  default(value: O): ZodType<O>
}

function make<O>(kind: string, extra: Record<string, unknown> = {}): ZodType<O> {
  const t: ZodType<O> = {
    _output: undefined as unknown as O,
    kind,
    ...extra,
    optional() {
      return make<O | undefined>(`${kind}?`, extra)
    },
    nullable() {
      return make<O | null>(`${kind}|null`, extra)
    },
    describe() {
      return this
    },
    default() {
      return make<O>(kind, extra)
    },
  }
  return t
}

export const z = {
  object<S extends Record<string, ZodType>>(shape: S): ZodType<Flatten<{ [K in keyof S]: S[K]["_output"] }>> {
    return make("object", { shape })
  },
  string(): ZodType<string> {
    return make("string")
  },
  number(): ZodType<number> {
    return make("number")
  },
  boolean(): ZodType<boolean> {
    return make("boolean")
  },
  unknown(): ZodType<unknown> {
    return make("unknown")
  },
  array<T extends ZodType>(item: T): ZodType<T["_output"][]> {
    return make("array", { item })
  },
  record<K extends ZodType<string>, V extends ZodType>(_key: K, value: V): ZodType<Record<string, V["_output"]>> {
    return make("record", { value })
  },
  literal<T extends string | number | boolean>(value: T): ZodType<T> {
    return make("literal", { value })
  },
  enum<T extends readonly [string, ...string[]]>(values: T): ZodType<T[number]> {
    return make("enum", { values })
  },
  union<T extends readonly [ZodType, ...ZodType[]]>(types: T): ZodType<T[number]["_output"]> {
    return make("union", { types })
  },
}

// Type-only namespace merged onto the value above: enables `z.infer<typeof schema>`.
// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace z {
  export type infer<T extends ZodType> = T["_output"]
}
