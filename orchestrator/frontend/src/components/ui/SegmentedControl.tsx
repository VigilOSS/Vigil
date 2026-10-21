import type { ReactNode } from "react";
import "../../styles/ui.css";

export type SegmentedOption<T extends string> = {
  value: T;
  label: ReactNode;
  /** Count beside the label; null or undefined while unknown (no count shown). */
  count?: number | null;
  /** The count covers only loaded rows; more exist ("1,000+"). */
  countPartial?: boolean;
  /** Plain-language definition of the option, shown on hover and to assistive technology. */
  description?: string;
  disabled?: boolean;
};

type SegmentedControlProps<T extends string> = {
  /** Accessible name of the group, e.g. "Coverage view". */
  label: string;
  value: T;
  options: SegmentedOption<T>[];
  onChange: (value: T) => void;
  className?: string;
};

/**
 * One-of-N switch for views and scopes (pressed buttons in a group). Every
 * view switch uses it: Coverage "Open work by reason / All items", HTTP
 * "Endpoint inventory / Captured exchanges", Findings "Grouped / Table".
 *
 *   <SegmentedControl label="HTTP view" value={view} onChange={setView}
 *     options={[{ value: "inventory", label: "Endpoint inventory", count: total }, { value: "exchanges", label: "Captured exchanges" }]} />
 */
export function SegmentedControl<T extends string>({ label, value, options, onChange, className }: SegmentedControlProps<T>) {
  return (
    <div className={["ui-segmented", className].filter(Boolean).join(" ")} role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={option.value === value}
          disabled={option.disabled}
          title={option.description}
          onClick={() => { if (option.value !== value) onChange(option.value); }}
        >
          <span>{option.label}</span>
          {option.count != null && (
            <span className="ui-segmented-count">{option.count.toLocaleString("en-US")}{option.countPartial ? "+" : ""}</span>
          )}
          {option.description && <span className="sr-only">: {option.description}</span>}
        </button>
      ))}
    </div>
  );
}

export type Scope = "attention" | "all";

type ScopeToggleProps = {
  scope: Scope;
  onChange: (scope: Scope) => void;
  /** Rows that need the operator under this tab's rule; null while unknown. */
  attentionCount: number | null | undefined;
  /** Every row; null while unknown. */
  allCount: number | null | undefined;
  /** This tab's rule in one sentence, e.g. "Failed, timed-out, killed or lost runs, and runs whose output was not kept." */
  attentionRule: string;
  /** Counts cover only loaded rows (a windowed ledger); shows "N+". */
  partial?: boolean;
  /** Accessible name; defaults to "Scope". */
  label?: string;
  className?: string;
};

/**
 * The "what needs me" scope every list tab offers, in one wording:
 * "Needs attention N · All N". The rule behind "needs attention" is the
 * tab's own and is always reachable (hover and screen readers).
 *
 *   <ScopeToggle scope={scope} onChange={setScope} attentionCount={62} allCount={11941}
 *     attentionRule="Failed, timed-out, killed or lost runs." />
 */
export function ScopeToggle({ scope, onChange, attentionCount, allCount, attentionRule, partial, label = "Scope", className }: ScopeToggleProps) {
  return (
    <SegmentedControl<Scope>
      label={label}
      value={scope}
      onChange={onChange}
      className={["ui-scope-toggle", className].filter(Boolean).join(" ")}
      options={[
        { value: "attention", label: "Needs attention", count: attentionCount, countPartial: partial, description: attentionRule },
        { value: "all", label: "All", count: allCount, countPartial: partial },
      ]}
    />
  );
}
