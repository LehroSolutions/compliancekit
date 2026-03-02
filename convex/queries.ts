import { query } from "./_generated/server";
import { v } from "convex/values";

export const listScans = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("scans")
      .withIndex("by_scannedAt")
      .order("desc")
      .take(args.limit ?? 20);
  },
});

export const getScanFindings = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
  },
});

export const getScanRemediation = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("remediations")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .first();
  },
});

export const getRiskOverview = query({
  args: {},
  handler: async (ctx) => {
    const scans = await ctx.db.query("scans").collect();
    const high = scans.filter((s) => s.riskLevel === "high").length;
    const medium = scans.filter((s) => s.riskLevel === "medium").length;
    const low = scans.filter((s) => s.riskLevel === "low").length;
    return { total: scans.length, high, medium, low };
  },
});
