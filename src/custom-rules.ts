type RecordValue = Record<string, unknown>;

export type ValidatedCustomRule = RecordValue & {
  type: "allow_field" | "field" | "deny_string" | "response_deny_string";
};

const isRecord = (value: unknown): value is RecordValue =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasOwn = (value: RecordValue, key: string): boolean => Object.hasOwn(value, key);

const assertRuleKeys = (
  rule: RecordValue,
  index: number,
  required: readonly string[],
  optional: readonly string[],
): void => {
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(rule).find((key) => !allowed.has(key));
  if (unknown !== undefined) throw new TypeError(`custom.rules[${index}] contains unknown field ${unknown}`);
  const inherited = [...allowed].find((key) => key in rule && !hasOwn(rule, key));
  if (inherited !== undefined) throw new TypeError(`custom.rules[${index}] field ${inherited} must be an own property`);
  const missing = required.find((key) => !hasOwn(rule, key));
  if (missing !== undefined) throw new TypeError(`custom.rules[${index}] is missing required field ${missing}`);
};

const assertOptionalName = (rule: RecordValue, index: number): void => {
  if (hasOwn(rule, "name") && typeof rule.name !== "string") {
    throw new TypeError(`custom.rules[${index}].name must be a string`);
  }
};

const assertNonemptyString = (value: unknown, path: string): void => {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${path} must be a nonempty string`);
};

const isCustomScalar = (value: unknown): boolean =>
  typeof value === "string"
  || typeof value === "boolean"
  || (typeof value === "number" && Number.isFinite(value));

const assertAllowFieldRule = (rule: RecordValue, index: number): void => {
  assertRuleKeys(rule, index, ["type", "fieldPath", "values"], ["name", "actionScope", "attested", "operator"]);
  assertOptionalName(rule, index);
  assertNonemptyString(rule.fieldPath, `custom.rules[${index}].fieldPath`);
  if (hasOwn(rule, "actionScope")) assertNonemptyString(rule.actionScope, `custom.rules[${index}].actionScope`);
  if (hasOwn(rule, "attested") && rule.attested !== true) {
    throw new TypeError(`custom.rules[${index}].attested must equal true`);
  }
  if (hasOwn(rule, "operator")
    && !["contains", "starts_with", "ends_with", "matches", "equals"].includes(rule.operator as string)) {
    throw new TypeError(`custom.rules[${index}].operator is unsupported`);
  }
  if (!Array.isArray(rule.values) || rule.values.length === 0
    || rule.values.some((value) => typeof value !== "string" && !(typeof value === "number" && Number.isFinite(value)))) {
    throw new TypeError(`custom.rules[${index}].values must be a nonempty string or number array`);
  }
};

const assertFieldRule = (rule: RecordValue, index: number): void => {
  assertRuleKeys(rule, index, ["type", "fieldPath", "operator", "value"], ["name"]);
  assertOptionalName(rule, index);
  assertNonemptyString(rule.fieldPath, `custom.rules[${index}].fieldPath`);
  if (!["contains", "starts_with", "ends_with", "matches", "equals", "not_equals"].includes(rule.operator as string)) {
    throw new TypeError(`custom.rules[${index}].operator is unsupported`);
  }
  if (!isCustomScalar(rule.value)) {
    throw new TypeError(`custom.rules[${index}].value must be a string, finite number, or boolean`);
  }
};

const assertDenyStringRule = (rule: RecordValue, index: number): void => {
  assertRuleKeys(rule, index, ["type", "value"], ["name"]);
  assertOptionalName(rule, index);
  if (!isCustomScalar(rule.value)) {
    throw new TypeError(`custom.rules[${index}].value must be a string, finite number, or boolean`);
  }
};

const assertResponseDenyStringRule = (rule: RecordValue, index: number): void => {
  assertRuleKeys(rule, index, ["type", "value"], ["name"]);
  assertOptionalName(rule, index);
  assertNonemptyString(rule.value, `custom.rules[${index}].value`);
};

const validateRule = (value: unknown, index: number): ValidatedCustomRule => {
  if (!isRecord(value)) throw new TypeError(`custom.rules[${index}] must be an object`);
  if ("type" in value && !hasOwn(value, "type")) {
    throw new TypeError(`custom.rules[${index}] field type must be an own property`);
  }
  if (typeof value.type !== "string") throw new TypeError(`custom.rules[${index}].type must be a string`);
  if (value.type === "allow_field") assertAllowFieldRule(value, index);
  else if (value.type === "field") assertFieldRule(value, index);
  else if (value.type === "deny_string") assertDenyStringRule(value, index);
  else if (value.type === "response_deny_string") assertResponseDenyStringRule(value, index);
  else throw new TypeError(`Unsupported custom rule type ${value.type}`);
  return value as ValidatedCustomRule;
};

export const validateCustomRules = (custom: unknown): ValidatedCustomRule[] => {
  if (custom === undefined) return [];
  if (!isRecord(custom)) throw new TypeError("custom must be an object");
  if ("rules" in custom && !hasOwn(custom, "rules")) throw new TypeError("custom field rules must be an own property");
  if (!Array.isArray(custom.rules)) throw new TypeError("custom.rules must be an array");
  const rules = custom.rules;
  return Array.from({ length: rules.length }, (_, index) => validateRule(rules[index], index));
};
