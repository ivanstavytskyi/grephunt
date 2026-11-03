import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigation } from "@/lib/nav";
import { Archive, Check, ChevronRight, Container, FolderOpen, Plus, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SnykConnect } from "@/components/snyk-connect";
import { SelectedScannerParams } from "@/components/selected-scanner-params";
import type { ScannerGroup, ToolInfo } from "@/api/types";
import { fetchScanRules, fetchTools, startScan, type SnykStatus } from "@/lib/api";
import {
  buildInitialParams,
  paramsForScanners,
  summarizeToolParams,
  type ToolParamsState,
} from "@/lib/scanner-params";

const SCANNER_GROUPS: { id: ScannerGroup; label: string }[] = [
  { id: "code", label: "Application code" },
  { id: "secret", label: "Secrets" },
  { id: "dependency", label: "Dependencies" },
  { id: "iac", label: "Infrastructure" },
];

const schema = z.object({
  github: z.string(),
});

type FormValues = z.infer<typeof schema>;

const UPLOAD_LIMIT = "10 GB";

function isZipName(name: string): boolean {
  return name.toLowerCase().endsWith(".zip");
}

const SKIP_GROUPS_KEY = "grephunt.skipGroups.v2";
const CUSTOM_SKIP_KEY = "grephunt.customSkipDirs.v2";
// Keep in sync with SKIP_GROUPS in grephunt/scan_pipeline/scan_view.py (tests/test_scan_view.py checks it).
const FALLBACK_SKIP_GROUPS: { label: string; folders: string[] }[] = [
  { label: "Installed packages", folders: ["node_modules", "bower_components", "jspm_packages", "web_modules", "vendor", "Pods", "Carthage", ".venv", "venv", "site-packages", ".tox", ".nox", ".eggs"] },
  { label: "Build output", folders: ["build", "dist", "out", "target", "obj", "_build", "storybook-static", "DerivedData", "cmake-build-debug", "cmake-build-release", "bazel-out"] },
  { label: "Framework and bundler caches", folders: [".next", ".nuxt", ".svelte-kit", ".angular", ".expo", ".output", ".vercel", ".netlify", ".turbo", ".parcel-cache", ".cache", ".webpack", ".vite"] },
  { label: "Package manager caches", folders: [".gradle", ".m2", ".ivy2", ".cargo", ".pub-cache", ".yarn", ".pnpm-store"] },
  { label: "Test coverage and tool caches", folders: ["coverage", ".nyc_output", "htmlcov", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"] },
  { label: "Infrastructure tool state", folders: [".terraform", ".serverless", ".aws-sam"] },
  { label: "Version control", folders: [".git"] },
];
const FALLBACK_DEPENDENCY_SCANNERS = ["grype", "osv-scanner", "snyk-open-source", "syft"];
const FALLBACK_SECRET_SCANNERS = ["betterleaks", "gitleaks", "kingfisher", "secretlint", "trufflehog"];

function isImageTarName(name: string): boolean {
  return name.toLowerCase().endsWith(".tar");
}

export function NewScanPage() {
  const tools = useQuery({ queryKey: ["tools"], queryFn: fetchTools });
  const scanRules = useQuery({ queryKey: ["scan-rules"], queryFn: fetchScanRules, staleTime: Infinity });
  const [selected, setSelected] = useState<string[]>([]);
  const [skipGroupSel, setSkipGroupSel] = useState<string[] | null>(() => {
    try {
      const raw = window.localStorage.getItem(SKIP_GROUPS_KEY);
      return raw ? (JSON.parse(raw) as string[]) : null;
    } catch {
      return null;
    }
  });
  const [customSkip, setCustomSkip] = useState<string[]>(() => {
    try {
      const raw = window.localStorage.getItem(CUSTOM_SKIP_KEY);
      return raw ? (JSON.parse(raw) as string[]) : [];
    } catch {
      return [];
    }
  });
  const [customInput, setCustomInput] = useState("");
  const persistSkip = (key: string, value: unknown) => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Storage can be unavailable; the choice still applies to this scan.
    }
  };
  const [toolParams, setToolParams] = useState<ToolParamsState>({});
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [folder, setFolder] = useState<File[] | null>(null);
  const zipInput = useRef<HTMLInputElement>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const imageMode = imageFile !== null;
  // The server's list is the source of truth; the copy here covers a server that predates /api/scan-rules.
  const skipGroups = scanRules.data?.skip_build_dirs.groups ?? FALLBACK_SKIP_GROUPS;
  const activeGroups = skipGroupSel ?? [];
  const skipDirs = [
    ...new Set([
      ...skipGroups.filter((group) => activeGroups.includes(group.label)).flatMap((group) => group.folders),
      ...customSkip,
    ]),
  ];
  const toggleGroup = (label: string) => {
    const base = skipGroupSel ?? [];
    const next = base.includes(label) ? base.filter((item) => item !== label) : [...base, label];
    setSkipGroupSel(next);
    persistSkip(SKIP_GROUPS_KEY, next);
  };
  const addCustomSkip = () => {
    const value = customInput.trim();
    if (!value || customSkip.includes(value)) {
      setCustomInput("");
      return;
    }
    const next = [...customSkip, value];
    setCustomSkip(next);
    persistSkip(CUSTOM_SKIP_KEY, next);
    setCustomInput("");
  };
  const removeCustomSkip = (value: string) => {
    const next = customSkip.filter((item) => item !== value);
    setCustomSkip(next);
    persistSkip(CUSTOM_SKIP_KEY, next);
  };
  const [rulesOpen, setRulesOpen] = useState(false);
  const [blockOpen, setBlockOpen] = useState(false);
  const dependencyScanners = scanRules.data?.skip_build_dirs.dependency_scanners ?? FALLBACK_DEPENDENCY_SCANNERS;
  const secretScanners = scanRules.data?.skip_build_dirs.secret_scanners ?? FALLBACK_SECRET_SCANNERS;
  const [snykConnected, setSnykConnected] = useState(false);
  const onSnyk = useCallback((status: SnykStatus) => setSnykConnected(status.connected), []);
  const folderInput = useRef<HTMLInputElement>(null);
  const { navigate } = useNavigation();
  const queryClient = useQueryClient();
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { github: "" },
  });

  // No scanner is preselected: the person picks every scanner to run.

  useEffect(() => {
    if (!tools.data?.length) return;
    setToolParams((current) => {
      const next = { ...current };
      for (const tool of tools.data) {
        if (tool.parameters?.length && !next[tool.name]) {
          next[tool.name] = buildInitialParams([tool])[tool.name];
        }
      }
      return next;
    });
  }, [tools.data]);

  const imageTools = (tools.data ?? []).filter((tool) => tool.scans_images).map((tool) => tool.name);
  const cloudTools = (tools.data ?? []).filter((tool) => tool.cloud).map((tool) => tool.name);
  const runnable = (names: string[]) =>
    names.filter(
      (name) => (!imageMode || imageTools.includes(name)) && (snykConnected || !cloudTools.includes(name)),
    );

  const applyImageScanners = () => {
    setSelected((current) => current.filter((name) => imageTools.includes(name)));
  };

  const chooseZip = (file: File | null) => {
    setZipFile(file);
    if (!file) return;
    setImageFile(null);
    setFolder(null);
  };

  const chooseImage = (file: File | null) => {
    setImageFile(file);
    if (!file) return;
    setZipFile(null);
    setFolder(null);
    applyImageScanners();
  };

  const mutation = useMutation({
    mutationFn: (values: FormValues) => {
      const scannersToRun = runnable(selected);
      return startScan({
        archive: folder ? null : imageFile ?? zipFile,
        folder,
        githubUrl: values.github,
        scanners: scannersToRun,
        params: paramsForScanners(scannersToRun, tools.data ?? [], toolParams),
        useDocker: true,
        skipDirs,
      });
    },
    onSuccess: async (scan) => {
      toast.success(`Scan of ${scan.target_label} started`);
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
      navigate(`/scans/${scan.id}`);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  return (
    <div className="mx-auto max-w-3xl px-8 py-10">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-signal">SAST</p>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight">New scan</h1>
      <p className="mt-2 max-w-xl text-sm leading-6 text-ink-muted">
        Scan source code from a zip or folder, or scan a saved Docker image (.tar from{" "}
        <span className="font-mono text-xs">docker save</span>). Nothing is executed on your machine.
      </p>

      <form
        className="mt-8 space-y-6"
        onSubmit={form.handleSubmit((values) => {
          if (!values.github.trim() && !zipFile && !imageFile && (!folder || folder.length === 0)) {
            toast.error("Add a zip, a Docker image .tar, a project folder, or a GitHub link.");
            return;
          }
          const scannersToRun = runnable(selected);
          if (scannersToRun.length === 0) {
            toast.error(
              imageMode
                ? "Select at least one scanner that supports container images (for example Trivy or Grype)."
                : "Select at least one scanner",
            );
            return;
          }
          mutation.mutate(values);
        })}
      >
        <label className="block">
          <span className="mb-1.5 block text-sm">GitHub repository</span>
          <Input
            placeholder="https://github.com/owner/repo"
            aria-label={`Public GitHub repository link. GrepHunt downloads a copy, up to ${UPLOAD_LIMIT}.`}
            title={`Public GitHub repository. GrepHunt downloads a copy, up to ${UPLOAD_LIMIT}.`}
            {...form.register("github")}
          />
        </label>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <UploadCard
            active={zipFile !== null}
            icon={Archive}
            title={zipFile ? zipFile.name : "Project zip"}
            hint={`Source archive (.zip), up to ${UPLOAD_LIMIT}`}
            dropLabel="Drop a .zip file here"
            onPick={() => zipInput.current?.click()}
            onDropFile={(file) => {
              if (!isZipName(file.name)) {
                toast.error("Use a .zip file for source code, or the Docker image card for a .tar.");
                return;
              }
              chooseZip(file);
            }}
          />
          <input
            ref={zipInput}
            type="file"
            accept=".zip,application/zip"
            className="sr-only"
            tabIndex={-1}
            aria-label={`Upload project zip, up to ${UPLOAD_LIMIT}`}
            onChange={(event) => {
              const file = event.target.files?.[0] ?? null;
              if (file && !isZipName(file.name)) {
                toast.error("Choose a .zip file.");
                event.target.value = "";
                return;
              }
              chooseZip(file);
              event.target.value = "";
            }}
          />

          <UploadCard
            active={imageFile !== null}
            icon={Container}
            title={imageFile ? imageFile.name : "Docker image"}
            hint={`Image tar from docker save, up to ${UPLOAD_LIMIT}. Not unpacked — scanned as an image.`}
            dropLabel="Drop a .tar image here"
            onPick={() => imageInput.current?.click()}
            onDropFile={(file) => {
              if (!isImageTarName(file.name)) {
                toast.error("Use a .tar from docker save (or OCI layout tar).");
                return;
              }
              chooseImage(file);
            }}
            footer={
              imageMode ? (
                <p className="mt-2 text-[11px] leading-4 text-signal">
                  Image scan · {imageTools.length > 0 ? imageTools.join(", ") : "Trivy, Grype, Syft, …"}
                </p>
              ) : (
                <p className="mt-2 font-mono text-[10px] leading-4 text-ink-muted">docker save -o app.tar myapp:tag</p>
              )
            }
          />
          <input
            ref={imageInput}
            type="file"
            accept=".tar,application/x-tar"
            className="sr-only"
            tabIndex={-1}
            aria-label={`Upload Docker image tar, up to ${UPLOAD_LIMIT}`}
            onChange={(event) => {
              const file = event.target.files?.[0] ?? null;
              if (file && !isImageTarName(file.name)) {
                toast.error("Choose a .tar file from docker save.");
                event.target.value = "";
                return;
              }
              chooseImage(file);
              event.target.value = "";
            }}
          />

          <UploadCard
            active={folder !== null && folder.length > 0}
            icon={FolderOpen}
            title={
              folder && folder.length > 0
                ? `${folder[0].webkitRelativePath.split("/")[0] || "Folder"} · ${folder.length} files`
                : "Project folder"
            }
            hint={`Folder on this computer, up to ${UPLOAD_LIMIT}`}
            dropLabel="Folder pick only (use the button)"
            onPick={() => folderInput.current?.click()}
            onDropFile={() => {
              toast.error("Use Choose a project folder to pick a directory.");
            }}
          />
          <input
            ref={folderInput}
            type="file"
            className="sr-only"
            multiple
            tabIndex={-1}
            aria-label={`Choose a project folder, up to ${UPLOAD_LIMIT}`}
            {...{ webkitdirectory: "", directory: "" }}
            onChange={(event) => {
              const picked = event.target.files ? Array.from(event.target.files) : [];
              setFolder(picked.length > 0 ? picked : null);
              if (picked.length > 0) {
                setZipFile(null);
                setImageFile(null);
              }
              event.target.value = "";
            }}
          />
        </div>

        <SnykConnect onChange={onSnyk} />

        <ScannerPicker
          tools={tools.data ?? []}
          selected={selected}
          onSelectedChange={setSelected}
          imageMode={imageMode}
          snykConnected={snykConnected}
          toolParams={toolParams}
        />

        <SelectedScannerParams
          tools={tools.data ?? []}
          selected={runnable(selected)}
          params={toolParams}
          onParamsChange={(tool, values) => setToolParams((current) => ({ ...current, [tool]: values }))}
          expanded={expandedTool}
          onExpandedChange={setExpandedTool}
        />

        {!imageMode && (
          <fieldset className="rounded-lg border border-ink-line bg-ink-panel px-4 py-3">
            <button
              type="button"
              aria-expanded={blockOpen}
              onClick={() => setBlockOpen((value) => !value)}
              className="flex w-full items-center gap-2 px-1 text-left focus-visible:outline-none"
            >
              <ChevronRight className={`size-3.5 text-ink-muted transition-transform ${blockOpen ? "rotate-90" : ""}`} aria-hidden="true" />
              <span className="text-xs font-medium text-ink-muted">Scan rules — excluded folders</span>
              <span className="ml-auto text-[11px] text-ink-muted">
                {skipDirs.length === 0 ? "none excluded" : `${skipDirs.length} folder${skipDirs.length === 1 ? "" : "s"} excluded`}
              </span>
            </button>
            {blockOpen && (
              <div className="mt-3">
            <p className="text-xs leading-5 text-ink-muted">
              Folders left out of code and IaC scanners. Pick the lists to exclude, or add your own. Dependency and
              secret scanners still read the whole project.
            </p>

            <div className="mt-3 space-y-1">
              {skipGroups.map((group) => {
                const on = activeGroups.includes(group.label);
                return (
                  <label
                    key={group.label}
                    className="group flex cursor-pointer items-start gap-3 rounded-md px-1 py-1 hover:bg-ink-raised/50"
                  >
                    <span className="relative mt-0.5 flex size-4 shrink-0">
                      <input
                        type="checkbox"
                        checked={on}
                        onChange={() => toggleGroup(group.label)}
                        className="peer absolute inset-0 m-0 size-4 cursor-pointer appearance-none rounded-[4px] border border-ink-line bg-ink-bg transition-colors checked:border-ink-muted/70 checked:bg-ink-raised group-hover:border-ink-muted/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ink-muted/70"
                      />
                      <Check
                        aria-hidden="true"
                        strokeWidth={3}
                        className="pointer-events-none absolute inset-0 m-auto size-3 text-ink-text/85 opacity-0 transition-opacity peer-checked:opacity-100"
                      />
                    </span>
                    <span className="min-w-0">
                      <span className="block text-sm text-ink-text">{group.label}</span>
                      <span className="mt-0.5 block break-all font-mono text-[11px] leading-4 text-ink-muted">
                        {group.folders.join(", ")}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>

            <div className="mt-3 border-t border-ink-line pt-3">
              <p className="mb-1.5 text-xs text-ink-muted">
                Add your own folder or glob to exclude, or start with <span className="font-mono">!</span> to keep a folder a checked list would exclude (for example <span className="font-mono">!vendor</span>, <span className="font-mono">fixtures</span>, <span className="font-mono">**/testdata</span>).
              </p>
              <div className="flex items-center gap-2">
                <Input
                  value={customInput}
                  onChange={(event) => setCustomInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addCustomSkip();
                    }
                  }}
                  placeholder="folder name or glob"
                  aria-label="Add a folder or glob to exclude"
                  className="h-9 flex-1"
                />
                <button
                  type="button"
                  onClick={addCustomSkip}
                  aria-label="Add folder to exclude"
                  className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
                >
                  <Plus className="size-4" aria-hidden="true" />
                </button>
              </div>
              {customSkip.length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-1.5">
                  {customSkip.map((item) => (
                    <li
                      key={item}
                      className="inline-flex items-center gap-1 rounded bg-ink-raised px-2 py-0.5 font-mono text-[11px] text-ink-text"
                    >
                      {item}
                      <button
                        type="button"
                        onClick={() => removeCustomSkip(item)}
                        aria-label={`Remove ${item}`}
                        className="text-ink-muted hover:text-ink-text"
                      >
                        <X className="size-3" aria-hidden="true" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {skipDirs.length === 0 && (
              <p className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs leading-5 text-amber-100">
                Nothing is excluded — scanners will also read node_modules, .git and build output. This is slower,
                noisier, and can exhaust memory on large projects.
              </p>
            )}

            <button
              type="button"
              aria-expanded={rulesOpen}
              onClick={() => setRulesOpen((value) => !value)}
              className="mt-3 inline-flex items-center gap-1 rounded text-xs text-ink-muted hover:text-ink-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ink-muted/70"
            >
              <ChevronRight className={`size-3.5 transition-transform ${rulesOpen ? "rotate-90" : ""}`} aria-hidden="true" />
              {rulesOpen ? "Hide details" : "How exclusion works"}
            </button>
            {rulesOpen && (
              <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-ink-muted marker:text-ink-line">
                <li>
                  A folder is excluded when its name matches a checked list exactly, at any depth (frontend/dist,
                  packages/api/node_modules). Custom entries also accept globs and, with an re: prefix, Python regular expressions (re:^vendor/.*); a leading ! keeps a folder in the scan (!vendor, !re:.*/keep).
                </li>
                <li>Your files are not changed. Scanners get a copy of the project without these folders.</li>
                <li>
                  Dependency scanners ({dependencyScanners.join(", ")}) always scan the whole project: they read
                  installed packages.
                </li>
                <li>
                  Secret scanners ({secretScanners.join(", ")}) always scan the whole project, including build output
                  and git history, where keys leak.
                </li>
              </ul>
            )}
              </div>
            )}
          </fieldset>
        )}

        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Starting" : "Start scan"}
        </Button>
      </form>
    </div>
  );
}

function UploadCard({
  active,
  icon: Icon,
  title,
  hint,
  dropLabel,
  onPick,
  onDropFile,
  footer,
}: {
  active: boolean;
  icon: typeof Archive;
  title: string;
  hint: string;
  dropLabel: string;
  onPick: () => void;
  onDropFile: (file: File) => void;
  footer?: ReactNode;
}) {
  return (
    <div
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        const file = event.dataTransfer.files?.[0];
        if (file) onDropFile(file);
      }}
    >
      <button
        type="button"
        title={dropLabel}
        aria-label={`${title}. ${hint}`}
        onClick={onPick}
        className={`flex h-full min-h-[9.5rem] w-full flex-col items-center justify-center rounded-lg border border-dashed px-3 py-6 text-center ${
          active ? "border-signal/60 bg-signal/10" : "border-ink-line bg-ink-panel hover:border-signal/50"
        }`}
      >
        <Icon className="size-5 text-ink-muted" aria-hidden="true" />
        <span className="mt-2 line-clamp-2 text-sm">{title}</span>
        <span className="mt-1 text-xs leading-5 text-ink-muted">{hint}</span>
        {footer}
      </button>
    </div>
  );
}

function ScannerPicker({
  tools,
  selected,
  onSelectedChange,
  imageMode,
  snykConnected,
  toolParams,
}: {
  tools: ToolInfo[];
  selected: string[];
  onSelectedChange: (names: string[]) => void;
  imageMode: boolean;
  snykConnected: boolean;
  toolParams: ToolParamsState;
}) {
  const byGroup = SCANNER_GROUPS.map((group) => ({
    ...group,
    tools: tools.filter((tool) => tool.group === group.id),
  })).filter((group) => group.tools.length > 0);

  return (
    <fieldset>
      <legend className="mb-2 text-sm">Scanners</legend>
      <p className="mb-3 text-xs leading-5 text-ink-muted">
        Select scanners to run. Adjust options in the block below when a scanner is selected.
      </p>
      {imageMode && (
        <p className="mb-3 text-xs leading-5 text-ink-muted">
          Image scan: only scanners that read container images can run. The others are turned off.
        </p>
      )}
      <div className="space-y-5">
        {byGroup.map((group) => (
          <div key={group.id}>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-muted">{group.label}</p>
            <ul className="grid gap-2 sm:grid-cols-2">
              {group.tools.map((tool) => {
                const needsLogin = tool.cloud && !snykConnected;
                const blocked = (imageMode && !tool.scans_images) || needsLogin;
                const on = selected.includes(tool.name) && !blocked;
                const paramSummary =
                  on && tool.parameters?.length ? summarizeToolParams(tool, toolParams[tool.name]) : "";
                return (
                  <li key={tool.name}>
                    <button
                      type="button"
                      disabled={blocked}
                      title={
                        needsLogin
                          ? "Connect Snyk first"
                          : blocked
                            ? `${tool.name} does not scan container images`
                            : tool.cloud
                              ? "Runs in the vendor's cloud: project data leaves this machine"
                              : undefined
                      }
                      onClick={() =>
                        onSelectedChange(
                          selected.includes(tool.name)
                            ? selected.filter((item) => item !== tool.name)
                            : [...selected, tool.name],
                        )
                      }
                      aria-pressed={on}
                      aria-label={`${on ? "Deselect" : "Select"} scanner ${tool.name}`}
                      className={`w-full rounded-md border px-3 py-2.5 text-left leading-snug disabled:cursor-not-allowed disabled:opacity-40 ${
                        on ? "border-signal/60 bg-signal/10" : "border-ink-line hover:border-ink-muted/60"
                      }`}
                    >
                      <span className="font-mono text-sm">{tool.name}</span>
                      <span className="mt-0.5 font-mono text-[10px] leading-4 text-ink-muted">
                        v{tool.version}
                        {tool.scans_images ? " · image" : ""}
                        {tool.cloud ? " · cloud" : ""}
                      </span>
                      {tool.languages && (
                        <span className="mt-1.5 block text-xs text-ink-muted">
                          <span className="text-ink-text/80">Languages:</span> {tool.languages}
                        </span>
                      )}
                      {tool.purpose && (
                        <span className="mt-0.5 block text-xs leading-5 text-ink-muted">{tool.purpose}</span>
                      )}
                      {paramSummary && (
                        <span className="mt-1.5 block truncate text-xs text-signal/90">Run: {paramSummary}</span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </fieldset>
  );
}
