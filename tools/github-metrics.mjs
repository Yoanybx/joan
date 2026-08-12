#!/usr/bin/env node

import { appendFileSync } from "node:fs";

const API_VERSION = "2022-11-28";
const repository = process.argv[2] ?? process.env.GITHUB_REPOSITORY;
const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;

if (!repository || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
  process.stderr.write("github-metrics: expected owner/repository\n");
  process.exit(2);
}

const headers = {
  Accept: "application/vnd.github+json",
  "User-Agent": "joan-github-metrics-v1",
  "X-GitHub-Api-Version": API_VERSION,
};
if (token) headers.Authorization = `Bearer ${token}`;

async function request(path) {
  const response = await fetch(`https://api.github.com${path}`, { headers });
  if (!response.ok) {
    return { available: false, status: response.status, value: null };
  }
  return { available: true, status: response.status, value: await response.json() };
}

async function required(path, label) {
  const result = await request(path);
  if (!result.available) {
    throw new Error(`${label} request failed with HTTP ${result.status}`);
  }
  return result.value;
}

async function issueCount(query) {
  const parameters = new URLSearchParams({ q: `repo:${repository} is:issue ${query}`, per_page: "1" });
  const result = await request(`/search/issues?${parameters.toString()}`);
  return result.available ? result.value.total_count : null;
}

function sumReleaseDownloads(releases) {
  return releases.reduce(
    (total, release) => total + release.assets.reduce((subtotal, asset) => subtotal + asset.download_count, 0),
    0,
  );
}

function sumTrafficDays(days, field) {
  return days.reduce((total, day) => total + day[field], 0);
}

function trafficSnapshot(views, clones) {
  if (!token) {
    return {
      status: "token-not-provided",
      window_days: 14,
      views: null,
      unique_visitors: null,
      clones: null,
      unique_cloners: null,
    };
  }
  if (!views.available || !clones.available) {
    return {
      status: "permission-unavailable",
      window_days: 14,
      views: null,
      unique_visitors: null,
      clones: null,
      unique_cloners: null,
    };
  }
  return {
    status: "available",
    window_days: 14,
    views: sumTrafficDays(views.value.views, "count"),
    unique_visitors: sumTrafficDays(views.value.views, "uniques"),
    clones: sumTrafficDays(clones.value.clones, "count"),
    unique_cloners: sumTrafficDays(clones.value.clones, "uniques"),
  };
}

function summary(snapshot) {
  const traffic = snapshot.traffic_window;
  const unavailable = "unavailable";
  return [
    "# JOAN product metrics",
    "",
    `Repository: \`${snapshot.repository}\``,
    `Generated: \`${snapshot.generated_at}\``,
    "",
    "| Signal | Value |",
    "| --- | ---: |",
    `| Stars | ${snapshot.adoption_proxies.stars} |`,
    `| Forks | ${snapshot.adoption_proxies.forks} |`,
    `| Release downloads | ${snapshot.adoption_proxies.release_downloads} |`,
    `| Declared adoption reports | ${snapshot.adoption_proxies.declared_adoption_reports ?? unavailable} |`,
    `| Open bugs | ${snapshot.quality.open_bugs ?? unavailable} |`,
    `| Closed bugs | ${snapshot.quality.closed_bugs ?? unavailable} |`,
    `| 14-day unique visitors | ${traffic.unique_visitors ?? unavailable} |`,
    `| 14-day unique cloners | ${traffic.unique_cloners ?? unavailable} |`,
    "",
    "> These are GitHub adoption proxies, not a claim about active installations or runtime frequency.",
    "",
  ].join("\n");
}

try {
  const [metadata, releases, runs, openBugs, closedBugs, adopters, views, clones] = await Promise.all([
    required(`/repos/${repository}`, "repository metadata"),
    required(`/repos/${repository}/releases?per_page=100`, "releases"),
    request(`/repos/${repository}/actions/runs?per_page=100`),
    issueCount("label:bug is:open"),
    issueCount("label:bug is:closed"),
    issueCount("label:adoption-report"),
    token ? request(`/repos/${repository}/traffic/views`) : Promise.resolve({ available: false }),
    token ? request(`/repos/${repository}/traffic/clones`) : Promise.resolve({ available: false }),
  ]);

  const workflowRuns = runs.available ? runs.value.workflow_runs : [];
  const snapshot = {
    schema: "joan.github-metrics-snapshot.v1",
    repository,
    generated_at: new Date().toISOString(),
    source: "github-rest-api",
    privacy: {
      hidden_runtime_telemetry: false,
      personal_identifiers_collected: false,
      scope: "repository-level aggregate signals",
    },
    adoption_proxies: {
      stars: metadata.stargazers_count,
      forks: metadata.forks_count,
      subscribers: metadata.subscribers_count,
      release_downloads: sumReleaseDownloads(releases),
      declared_adoption_reports: adopters,
    },
    quality: {
      open_issues: metadata.open_issues_count,
      open_bugs: openBugs,
      closed_bugs: closedBugs,
    },
    delivery: {
      releases: releases.length,
      latest_release: releases[0]?.tag_name ?? null,
      workflow_runs_sampled: workflowRuns.length,
      successful_workflow_runs: workflowRuns.filter((run) => run.conclusion === "success").length,
      failed_workflow_runs: workflowRuns.filter((run) => run.conclusion === "failure").length,
    },
    traffic_window: trafficSnapshot(views, clones),
    limitations: [
      "GitHub traffic covers a rolling 14-day window.",
      "Clones, downloads, stars and declarations do not equal active users.",
      "Runtime frequency is unavailable because JOAN sends no hidden telemetry.",
      "Private repository visibility and token permissions can make fields unavailable.",
    ],
  };

  process.stdout.write(`${JSON.stringify(snapshot)}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary(snapshot), "utf8");
  }
} catch (error) {
  process.stderr.write(`github-metrics: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
