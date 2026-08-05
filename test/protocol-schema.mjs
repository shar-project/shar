import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaFiles = [
  "admin-audit.schema.json",
  "audit-event.schema.json",
  "challenge.schema.json",
  "error.schema.json",
  "fallback-assertion.schema.json",
  "fallback-completion.schema.json",
  "redeem.schema.json",
  "siteverify.schema.json",
  "trust-credit.schema.json",
  "trust-evaluation.schema.json",
  "work-quote.schema.json",
];

let validatorsPromise;

export function protocolValidators() {
  validatorsPromise ??= createValidators();
  return validatorsPromise;
}

async function createValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  ajv.addKeyword({
    keyword: "x-shar-maxUtf8Bytes",
    type: "string",
    schemaType: "number",
    validate: (maximum, value) =>
      new TextEncoder().encode(value).length <= maximum,
  });
  ajv.addKeyword({
    keyword: "x-shar-noControlCharacters",
    type: "string",
    schemaType: "boolean",
    validate: (enabled, value) => !enabled || !/\p{Cc}/u.test(value),
  });
  ajv.addKeyword({
    keyword: "x-shar-minUtf8Bytes",
    type: "string",
    schemaType: "number",
    validate: (minimum, value) =>
      new TextEncoder().encode(value).length >= minimum,
  });
  for (const file of schemaFiles) {
    const schema = JSON.parse(
      await readFile(new URL(`../protocol/${file}`, import.meta.url), "utf8"),
    );
    ajv.addSchema(schema);
  }
  const reference = (document, definition) => ({
    $ref: `https://shar.dev/schema/v1/${document}.json${definition ? `#/$defs/${definition}` : ""}`,
  });
  return Object.freeze({
    challengeRequest: ajv.compile(reference("challenge", "request")),
    challengeResponse: ajv.compile(reference("challenge", "response")),
    redeemRequest: ajv.compile(reference("redeem", "request")),
    redeemResponse: ajv.compile(reference("redeem", "response")),
    siteVerifyRequest: ajv.compile(reference("siteverify", "request")),
    siteVerifyResponse: ajv.compile(reference("siteverify", "response")),
    fallbackRequest: ajv.compile(reference("fallback-completion", "request")),
    fallbackResponse: ajv.compile(reference("fallback-completion", "response")),
    fallbackAssertion: ajv.compile(reference("fallback-assertion")),
    error: ajv.compile(reference("error")),
    auditEvent: ajv.compile(reference("audit-event")),
    adminAudit: ajv.compile(reference("admin-audit")),
  });
}

export function assertProtocolSchema(validate, value, label) {
  if (validate(value)) return;
  const details = (validate.errors ?? [])
    .map(
      (error) =>
        `${error.instancePath || "/"} ${error.message ?? "is invalid"}`,
    )
    .join("; ");
  throw new Error(`${label} violates its protocol schema: ${details}`);
}

export async function validateProtocolResponse(path, status, value, label) {
  const validators = await protocolValidators();
  if (status < 200 || status >= 300) {
    assertProtocolSchema(validators.error, value, `${label} error`);
    return;
  }
  const validate =
    {
      "/v1/challenges": validators.challengeResponse,
      "/v1/challenges/redeem": validators.redeemResponse,
      "/v1/siteverify": validators.siteVerifyResponse,
      "/v1/fallback/complete": validators.fallbackResponse,
    }[path] ?? undefined;
  if (validate) assertProtocolSchema(validate, value, label);
}
