import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigation } from "@/lib/nav";
import { Archive, Container, FolderOpen, Wand2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SnykConnect } from "@/components/snyk-connect";
import { SelectedScannerParams } from "@/components/selected-scanner-params";
import type { ScannerGroup, ToolInfo } from "@/api/types";
import { analyzeTarget, fetchTools, startScan, type ScannerAdvice, type SnykStatus } from "@/lib/api";
import { readSavedAiKey } from "@/lib/ai-storage";
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

function isImageTarName(name: string): boolean {
  return name.toLowerCase().endsWith(".tar");
}

export function NewScanPage() {
  const tools = useQuery({ queryKey: ["tools"], queryFn: fetchTools });
  const [selected, setSelected] = useState<string[]>(["semgrep", "trivy"]);
  const [toolParams, setToolParams] = useState<ToolParamsState>({});
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [folder, setFolder] = useState<File[] | null>(null);
  const zipInput = useRef<HTMLInputElement>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const imageMode = imageFile !== null;
  const [advising, setAdvising] = useState(false);
  const [advice, setAdvice] = useState<ScannerAdvice | null>(null);
  const [adviceError, setAdviceError] = useState("");
  const [snykConnected, setSnykConnected] = useState(false);
  const onSnyk = useCallback((status: SnykStatus) => setSnykConnected(status.connected), []);
  const folderInput = useRef<HTMLInputElement>(null);
  const { navigate } = useNavigation();
  const queryClient = useQueryClient();
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { github: "" },
  });

  // Start from the scanners the catalog marks as default (one or two strong tools per category).
  const defaultsApplied = useRef(false);
  useEffect(() => {
    if (!tools.data?.length || defaultsApplied.current) return;
    defaultsApplied.current = true;
    const defaults = tools.data.filter((tool) => tool.default_enabled && !tool.cloud).map((tool) => tool.name);
    if (defaults.length) setSelected(defaults);
  }, [tools.data]);

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
  const defaultImageTools = (tools.data ?? [])
    .filter((tool) => tool.scans_images && tool.default_enabled)
    .map((tool) => tool.name);

  const cloudTools = (tools.data ?? []).filter((tool) => tool.cloud).map((tool) => tool.name);
  const runnable = (names: string[]) =>
    names.filter(
      (name) => (!imageMode || imageTools.includes(name)) && (snykConnected || !cloudTools.includes(name)),
    );

  const applyImageScanners = () => {
    setSelected((current) => {
      const kept = current.filter((name) => imageTools.includes(name));
      return kept.length > 0 ? kept : defaultImageTools;
    });
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

        <SuggestScanners
          advising={advising}
          advice={advice}
          error={adviceError}
          disabled={imageMode}
          onRun={async () => {
            const github = form.getValues("github").trim();
            if (!github && !zipFile && (!folder || folder.length === 0)) {
              setAdviceError("Add a zip, a project folder, or a GitHub link first.");
              return;
            }
            setAdvising(true);
            setAdviceError("");
            setAdvice(null);
            try {
              const saved = readSavedAiKey();
              const result = await analyzeTarget({
                archive: zipFile,
                folder,
                githubUrl: github,
                ai: saved ? { provider: saved.provider, apiKey: saved.apiKey, model: saved.model } : null,
              });
              setAdvice(result);
              const runnableRecommended = result.recommended.filter((name) => !cloudTools.includes(name));
              if (runnableRecommended.length > 0) setSelected(runnableRecommended);
            } catch (error) {
              setAdviceError(error instanceof Error ? error.message : "Could not analyze the project");
            } finally {
              setAdvising(false);
            }
          }}
        />

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

function SuggestScanners({ advising, advice, error, disabled, onRun }: {
  advising: boolean;
  advice: ScannerAdvice | null;
  error: string;
  disabled: boolean;
  onRun: () => void;
}) {
  if (disabled) return null;
  return (
    <div className="space-y-2">
      <button
        type="button"
        disabled={advising}
        onClick={onRun}
        title="Build the project map and recommend the scanners that fit this project. With an AI key, the model reviews the choice."
        className="inline-flex h-10 items-center justify-center gap-1.5 rounded-md border border-signal/50 bg-ink-panel px-4 text-sm font-medium text-ink-text hover:bg-signal/10 disabled:opacity-40"
      >
        <Wand2 className="size-4" />
        {advising ? "Analyzing the project…" : "Suggest scanners for this project"}
      </button>
      {error && <p className="text-xs text-rose-200">{error}</p>}
      {advice && (
        <div className="space-y-2 rounded-lg border border-ink-line bg-ink-panel p-3 text-xs">
          <p className="text-[11px] uppercase tracking-wide text-ink-muted">
            Recommended {advice.source === "ai" ? "· reviewed by AI" : "· from the project map"}
            {advice.label ? ` · ${advice.label}` : ""} — selected below
          </p>
          {advice.summary && <p className="text-ink-text/90">{advice.summary}</p>}
          {(advice.stack?.frameworks?.length || advice.stack?.datastores?.length) ? (
            <p className="text-ink-muted">
              Stack: {[...(advice.stack?.frameworks ?? []), ...(advice.stack?.datastores ?? [])].join(", ")}
            </p>
          ) : null}
          <ul className="space-y-1">
            {advice.recommended.map((name) => (
              <li key={name} className="flex gap-2">
                <span className="w-28 shrink-0 font-mono text-ink-text">{name}</span>
                <span className="text-ink-muted">{advice.reasons[name]}</span>
              </li>
            ))}
          </ul>
          {advice.note && <p className="text-amber-200/80">{advice.note}</p>}
        </div>
      )}
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
