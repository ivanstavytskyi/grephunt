import { Command } from "cmdk";
import { FolderSearch, Plus } from "lucide-react";
import { useNavigation } from "@/lib/nav";

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { navigate } = useNavigation();

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/50" onClick={() => onOpenChange(false)}>
      <Command
        className="mx-auto mt-24 w-full max-w-lg overflow-hidden rounded-xl border border-ink-line bg-ink-panel text-ink-text shadow-none"
        onClick={(event) => event.stopPropagation()}
        label="Commands"
      >
        <Command.Input
          autoFocus
          placeholder="Command or filter"
          className="h-11 w-full border-b border-ink-line bg-transparent px-3 text-sm outline-none"
        />
        <Command.List className="max-h-72 overflow-auto p-2">
          <Command.Empty className="px-2 py-6 text-center text-sm text-ink-muted">Nothing found</Command.Empty>
          <Command.Group heading="Scan" className="text-xs text-ink-muted">
            <Command.Item
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-ink-text aria-selected:bg-ink-raised"
              onSelect={() => {
                navigate("/");
                onOpenChange(false);
              }}
            >
              <Plus className="size-4" /> New scan
            </Command.Item>
            <Command.Item
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-ink-text aria-selected:bg-ink-raised"
              onSelect={() => {
                navigate("/");
                onOpenChange(false);
              }}
            >
              <FolderSearch className="size-4" /> Choose a folder or an archive
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}
