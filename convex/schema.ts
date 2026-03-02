import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  scans: defineTable({
    documentId: v.string(),
    textLength: v.number(),
    findingsCount: v.number(),
    riskLevel: v.string(),
    riskScore: v.number(),
    scannedAt: v.number(),
    userId: v.optional(v.string()),
  })
    .index("by_scannedAt", ["scannedAt"])
    .index("by_riskLevel", ["riskLevel"]),

  findings: defineTable({
    scanId: v.id("scans"),
    piiType: v.string(),
    redactedValue: v.string(),
    startOffset: v.number(),
    popiaConditions: v.array(v.string()),
    severity: v.string(),
  }).index("by_scanId", ["scanId"]),

  remediations: defineTable({
    scanId: v.id("scans"),
    actions: v.array(v.object({
      condition: v.string(),
      action: v.string(),
      deadline: v.string(),
      priority: v.string(),
    })),
    generatedAt: v.number(),
  }).index("by_scanId", ["scanId"]),

  auditLog: defineTable({
    event: v.string(),
    detail: v.string(),
    userId: v.optional(v.string()),
    ipHash: v.optional(v.string()),
    timestamp: v.number(),
  }).index("by_timestamp", ["timestamp"]),
});
