import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigation } from "@/lib/nav";
import { Archive, FolderOpen, Minus, Plus, ScrollText } from "lucide-react";
import { useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { fetchTools, startScan } from "@/lib/api";

const schema = z.object({
  configs: z.string(),
  github: z.string(),
});

type FormValues = z.infer<typeof schema>;

export function NewScanPage() {
  const tools = useQuery({ queryKey: ["tools"], queryFn: fetchTools });
  const [selected, setSelected] = useState<string[]>(["semgrep", "trivy"]);
  const [archive, setArchive] = useState<File | null>(null);
  const [folder, setFolder] = useState<File[] | null>(null);
  const zipInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const { navigate } = useNavigation();
  const queryClient = useQueryClient();
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { configs: "https://semgrep.dev/c/p/default", github: "" },
  });

  const mutation = useMutation({
    mutationFn: (values: FormValues) =>
      startScan({
        archive: folder ? null : archive,
        folder,
        githubUrl: values.github,
        scanners: selected,
        configs: values.configs,
        useDocker: true,
      }),
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
        Add the project as a zip file, or choose its folder. GrepHunt copies it and scans the code without running it.
      </p>

      <form
        className="mt-8 space-y-6"
        onSubmit={form.handleSubmit((values) => {
          if (!values.github.trim() && !archive && (!folder || folder.length === 0)) {
            toast.error("Add a zip file, choose a project folder, or paste a GitHub link.");
            return;
          }
          if (selected.length === 0) {
            toast.error("Select at least one scanner");
            return;
          }
          if (!values.configs.trim()) {
            toast.error("Add at least one rules path before starting the scan.");
            return;
          }
          mutation.mutate(values);
        })}
      >
        <label className="block">
          <span className="mb-1.5 block text-sm">GitHub repository</span>
          <Input
            placeholder="https://github.com/owner/repo"
            aria-label="Public GitHub repository link. GrepHunt downloads a copy, up to 500 MB."
            title="Public GitHub repository. GrepHunt downloads a copy, up to 500 MB."
            {...form.register("github")}
          />
        </label>

        <div className="grid grid-cols-2 gap-3">
          <div
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              const file = event.dataTransfer.files?.[0];
              if (!file) return;
              if (!file.name.toLowerCase().endsWith(".zip")) {
                toast.error("That file is not a zip. Drop a .zip file, or use Choose a project folder.");
                return;
              }
              setArchive(file);
              setFolder(null);
            }}
          >
            <button
              type="button"
              title="Upload one .zip of the project, up to 500 MB. You can also drop the file on this card."
              aria-label="Upload a zip file. One .zip of the project, up to 500 MB. You can also drop the file on this card."
              onClick={() => zipInput.current?.click()}
              className={`flex h-full w-full flex-col items-center justify-center rounded-lg border border-dashed px-4 py-8 text-center ${
                archive ? "border-signal/60 bg-signal/10" : "border-ink-line bg-ink-panel hover:border-signal/50"
              }`}
            >
              <Archive className="size-5 text-ink-muted" aria-hidden="true" />
              <span className="mt-2 text-sm">{archive ? archive.name : "Upload a zip file"}</span>
              <span className="mt-1 text-xs leading-5 text-ink-muted">
                One .zip of the project, up to 500 MB. You can drop it on this card.
              </span>
            </button>
            <input
              ref={zipInput}
              type="file"
              accept=".zip,application/zip"
              className="sr-only"
              tabIndex={-1}
              aria-label="Upload a zip file of the project, up to 500 MB"
              onChange={(event) => {
                const file = event.target.files?.[0] ?? null;
                if (file && !file.name.toLowerCase().endsWith(".zip")) {
                  toast.error("That file is not a zip. Choose a .zip file, or use Choose a project folder.");
                  event.target.value = "";
                  return;
                }
                setArchive(file);
                if (file) setFolder(null);
                event.target.value = "";
              }}
            />
          </div>
          <div>
            <button
              type="button"
              title="Choose the project folder on your computer. Its files are copied here, up to 500 MB."
              aria-label="Choose a project folder. Pick the folder on your computer. Its files are copied here, up to 500 MB."
              onClick={() => folderInput.current?.click()}
              className={`flex h-full w-full flex-col items-center justify-center rounded-lg border border-dashed px-4 py-8 text-center ${
                folder ? "border-signal/60 bg-signal/10" : "border-ink-line bg-ink-panel hover:border-signal/50"
              }`}
            >
              <FolderOpen className="size-5 text-ink-muted" aria-hidden="true" />
              <span className="mt-2 text-sm">
                {folder && folder.length > 0
                  ? `${folder[0].webkitRelativePath.split("/")[0] || "Folder"} · ${folder.length} files`
                  : "Choose a project folder"}
              </span>
              <span className="mt-1 text-xs leading-5 text-ink-muted">
                Pick the folder on your computer. Its files are copied here, up to 500 MB.
              </span>
            </button>
            <input
              ref={folderInput}
              type="file"
              className="sr-only"
              multiple
              tabIndex={-1}
              aria-label="Choose a project folder. Its files are copied here, up to 500 MB"
              {...{ webkitdirectory: "", directory: "" }}
              onChange={(event) => {
                const picked = event.target.files ? Array.from(event.target.files) : [];
                setFolder(picked.length > 0 ? picked : null);
                if (picked.length > 0) setArchive(null);
                event.target.value = "";
              }}
            />
          </div>
        </div>

        <fieldset>
          <legend className="mb-2 text-sm">Scanners</legend>
          <div className="flex flex-wrap gap-2">
            {(tools.data ?? []).map((tool) => {
              const on = selected.includes(tool.name);
              return (
                <button
                  key={tool.name}
                  type="button"
                  onClick={() =>
                    setSelected((current) =>
                      current.includes(tool.name)
                        ? current.filter((item) => item !== tool.name)
                        : [...current, tool.name],
                    )
                  }
                  aria-pressed={on}
                  aria-label={`${on ? "Deselect" : "Select"} scanner ${tool.name} ${tool.version}`}
                  className={`min-w-32 rounded-md border px-4 py-1 text-center leading-tight ${on ? "border-signal/60 bg-signal/10" : "border-ink-line"}`}
                >
                  <span className="block font-mono text-sm leading-4">{tool.name}</span>
                  <span className="font-mono text-[11px] leading-4 text-ink-muted">{tool.version}</span>
                </button>
              );
            })}
          </div>
        </fieldset>

        <RulesPath configs={form.watch("configs")} onChange={(value) => form.setValue("configs", value)} />

        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Starting" : "Start scan"}
        </Button>
      </form>
    </div>
  );
}

type RulePreview = {
  origin: string;
  source: string;
  total: number;
  shown: number;
  rules: Array<{ id: string; severity: string; message: string }>;
};

function sentence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return "Could not read these rules";
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

function RulesPath({ configs, onChange }: { configs: string; onChange: (value: string) => void }) {
  const [items, setItems] = useState(() => configs.split(",").map((item) => item.trim()).filter(Boolean));
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const publish = (next: string[]) => {
    const rows = next.length > 0 ? next : [""];
    setItems(rows);
    onChange(rows.map((item) => item.trim()).filter(Boolean).join(","));
  };

  const load = async (path: string) => {
    setLoading(true);
    setError("");
    setPreview(null);
    try {
      const response = await fetch(`/api/rules?config=${encodeURIComponent(path)}`);
      const body = await response.json();
      if (!response.ok) {
        setError(typeof body.detail === "string" ? sentence(body.detail) : "Could not read these rules");
        return;
      }
      setPreview(body as RulePreview);
    } catch {
      setError("Could not read these rules");
    } finally {
      setLoading(false);
    }
  };

  return (
    <fieldset>
      <legend className="mb-1.5 text-sm">Rules path</legend>
      <ul className="space-y-2">
        {items.map((item, index) => (
          <li key={index}>
            <div className="flex items-center gap-2">
              <span className="relative block min-w-0 flex-1">
                <Input
                  value={item}
                  className="pr-10"
                  aria-label={`Ruleset ${index + 1}`}
                  placeholder="https://semgrep.dev/c/p/default"
                  onChange={(event) => {
                    const next = [...items];
                    next[index] = event.target.value;
                    publish(next);
                    if (openIndex === index) setOpenIndex(null);
                  }}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-ink-muted hover:text-ink-text"
                  aria-expanded={openIndex === index}
                  aria-label={`Show rules for ruleset ${index + 1}`}
                  title="Show rules in this ruleset"
                  onClick={() => {
                    if (openIndex === index) {
                      setOpenIndex(null);
                      return;
                    }
                    setOpenIndex(index);
                    void load(item);
                  }}
                >
                  <ScrollText className="size-4" aria-hidden="true" />
                </button>
              </span>
              {index === 0 && (
                <button
                  type="button"
                  className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
                  aria-label="Add another ruleset"
                  title="Add another ruleset"
                  onClick={() => publish([...items, ""])}
                >
                  <Plus className="size-4" aria-hidden="true" />
                </button>
              )}
              <button
                type="button"
                className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
                aria-label={`Remove ruleset ${index + 1}`}
                title="Remove this ruleset"
                onClick={() => {
                  publish(items.filter((_, itemIndex) => itemIndex !== index));
                  setOpenIndex(null);
                }}
              >
                <Minus className="size-4" aria-hidden="true" />
              </button>
            </div>
            {openIndex === index && (
              <div className="mt-2 max-h-72 overflow-auto rounded-md border border-ink-line bg-ink-panel p-3 text-sm">
                {loading && <p className="text-ink-muted">Reading rules…</p>}
                {error && <p className="text-ink-muted">{error}</p>}
                {preview && preview.total === 0 && <p className="text-ink-muted">No rules in this ruleset.</p>}
                {preview && preview.total > 0 && (
                  <>
                    <p className="text-xs text-ink-muted">
                      {preview.origin}. {preview.source}. Showing {preview.shown} of {preview.total}.
                    </p>
                    <ul className="mt-3 space-y-3">
                      {preview.rules.map((rule, ruleIndex) => (
                        <li key={`${rule.id}-${ruleIndex}`}>
                          <p className="font-mono text-xs">
                            {rule.severity ? `${rule.severity} · ` : ""}
                            {rule.id}
                          </p>
                          {rule.message && <p className="mt-1 text-xs leading-5 text-ink-muted">{rule.message}</p>}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </fieldset>
  );
}
