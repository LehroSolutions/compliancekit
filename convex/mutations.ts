import { mutation } from "./_generated/server";
import { v } from "convex/values";

export const addScan = mutation({
  args: {
    documentId: v.string(),
    textLength: v.number(),
    findingsCount: v.number(),
    riskLevel: v.string(),
    riskScore: v.number(),
    userId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("scans", {
      ...args,
      scannedAt: Date.now(),
    });
  },
});

export const addFinding = mutation({
  args: {
    scanId: v.id("scans"),
    piiType: v.string(),
    redactedValue: v.string(),
    startOffset: v.number(),
    popiaConditions: v.array(v.string()),
    severity: v.string(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("findings", args);
  },
});

export const addRemediation = mutation({
  args: {
    scanId: v.id("scans"),
    actions: v.array(v.object({
      condition: v.string(),
      action: v.string(),
      deadline: v.string(),
      priority: v.string(),
    })),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("remediations", {
      ...args,
      generatedAt: Date.now(),
    });
  },
});
