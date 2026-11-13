# application-read-only.jq — shell-command write targets for application-read-only.sh.
#
# Input: the hook payload. Output: one tab-separated action per line, in command order,
# for the shell script to resolve against the filesystem:
#   cd <dir>      a later relative path resolves against <dir> ("-" = the previous directory)
#   pushd <dir>   cd that also stacks the current directory ("" = swap with the top entry)
#   popd          return to the top stacked directory
#   push / pop    a subshell opens / closes: ( ), $( ), backticks and a `bash -c` body;
#                 cd, pushd and popd inside it do not outlive it
#   w  <path>     the command would create, modify or remove <path>
#   r  <dir>      a git/jj subcommand that changes a work tree runs in <dir> ("" = cwd)
#   ra <path>     a pathspec of that subcommand, relative to the last `r` directory
#
# The tokenizer follows shell grammar far enough to find redirection targets, command
# words and their arguments: quotes, backslash escapes, ${VAR}, separators, subshells,
# $( ) and backticks, here-doc bodies (skipped), case patterns, compound-command
# keywords (if/then/do/{ ...), and one level of `bash -c` / `eval` bodies. It does not
# run, expand or interpret anything else.

def expand_word:
  # $HOME, $VIGIL_APPLICATION_DIR, $VIGIL_AGENT_ROOT, $ENGAGEMENT_DIR, $PWD and a
  # leading ~ expand; any other variable stays literal (and so resolves nowhere).
  reduce ($vars | to_entries[]) as $v (.;
      gsub("\\$\\{" + $v.key + "\\}|\\$" + $v.key + "(?![A-Za-z0-9_])"; $v.value))
  | if . == "~" then $vars.HOME
    elif startswith("~/") then $vars.HOME + .[1:]
    else . end;

def unquote:
  [scan("\"((?:[^\"\\\\]|\\\\.)*)\"|'([^']*)'|\\\\(.)|([^\"'\\\\]+)")
   | if .[0] != null then .[0] | gsub("\\\\(?<c>[\"\\\\$`])"; .c)
     elif .[1] != null then .[1]
     elif .[2] != null then .[2]
     else .[3] end]
  | add // "";

def strip_heredocs:
  # Drop each here-doc body (it is data on stdin), keep the rest of its operator line.
  gsub("(?<op><<-?[ \\t]*(?<q>['\"]?)(?<d>[A-Za-z_][A-Za-z0-9_]*)\\k<q>)(?<rest>[^\\n]*)\\n(?:[\\s\\S]*?\\n)??[ \\t]*\\k<d>[ \\t]*(?=\\n|$)";
       "\(.op)\(.rest)");

def tokens:
  [strip_heredocs
   | scan("(?<dup>[0-9]*>&[0-9-]+|<&[0-9-]+)|(?<out>&>>|&>|[0-9]*>>|[0-9]*>\\||[0-9]*>)|(?<in><<<|<<-?|<)|(?<sep>&&|\\|\\||;;|;|\\|&|\\||&|\\n|\\(|\\)|`)|(?<word>(?:\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*'|\\\\.|[^\\s\"'\\\\;&|<>()`])+)")
   | if .[0] != null then {t: "dup"}
     elif .[1] != null then {t: "out"}
     elif .[2] != null then {t: "in"}
     elif .[3] != null then {t: "sep", v: .[3]}
     else {t: "word", v: .[4]} end];

def segments:
  # A segment is one simple command ({words, redirs}) or a subshell mark ({mark}).
  # `(` and an opening backtick push, `)` and a closing backtick pop, except the `(`/`)`
  # around a case pattern: after `case WORD in` and after each `;;` the words up to `)`
  # are a pattern, not a command.
  def flush: .segs += [.cur] | .cur = {words: [], redirs: []};
  (reduce tokens[] as $tok ({segs: [], cur: {words: [], redirs: []}, pending: null, comment: false,
                             tick: false, cases: 0, header: false, pattern: false};
      if .comment then
        (if $tok.t == "sep" then .comment = false | flush else . end)
      elif .pattern then
        (if $tok.t == "word" and $tok.v == "esac" then .pattern = false | .cases -= 1
         elif $tok.t == "sep" and $tok.v == ")" then .pattern = false | flush
         else . end)
      elif $tok.t == "sep" then
        flush | .pending = null
        | if $tok.v == "(" then .segs += [{mark: "push"}]
          elif $tok.v == ")" then .segs += [{mark: "pop"}]
          elif $tok.v == "`" then .segs += [{mark: (if .tick then "pop" else "push" end)}] | .tick = (.tick | not)
          elif $tok.v == ";;" and .cases > 0 then .pattern = true
          else . end
      elif $tok.t == "out" then .pending = "out"
      elif $tok.t == "in" then .pending = "in"
      elif $tok.t == "dup" then .
      elif .pending == "out" then .cur.redirs += [$tok.v] | .pending = null
      elif .pending == "in" then .pending = null
      elif ($tok.v | startswith("#")) and (.cur.words | length) == 0 then .comment = true
      elif $tok.v == "case" and (.cur.words | length) == 0 then .cases += 1 | .header = true | .cur.words += [$tok.v]
      elif .header and $tok.v == "in" then .header = false | .pattern = true | .cur.words += [$tok.v]
      elif $tok.v == "esac" and (.cur.words | length) == 0 and .cases > 0 then .cases -= 1
      else .cur.words += [$tok.v] end)
   | .segs + [.cur])
  | map(select(.mark != null or (.words | length) > 0 or (.redirs | length) > 0));

def is_option: startswith("-") and . != "-";
def basename_of: sub(".*/"; "");

# Wrappers that run a later word as the real program, with the options of each that
# take a separate value (so `sudo -u acme rm x` runs rm, not `acme`).
def wrapper_value_options:
  {"sudo": ["-u", "-g", "-U", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-R", "--user", "--group",
            "--other-user", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type",
            "--command-timeout", "--chroot"],
   "doas": ["-u", "-C"],
   "env": ["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
   "nice": ["-n", "--adjustment"],
   "timeout": ["-s", "--signal", "-k", "--kill-after"],
   "stdbuf": ["-i", "-o", "-e", "--input", "--output", "--error"],
   "time": ["-f", "--format", "-o", "--output"],
   "ionice": ["-c", "-n", "-p", "--class", "--classdata"],
   "xargs": ["-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--arg-file", "--delimiter",
             "--max-args", "--max-procs", "--max-lines", "--max-chars", "--process-slot-var"],
   "exec": ["-a"], "command": [], "builtin": [], "nohup": []};

def skip_options($values):
  if length == 0 then .
  elif .[0] == "--" then .[1:]
  elif (.[0] | is_option) then (if (.[0] | IN($values[])) then .[2:] else .[1:] end) | skip_options($values)
  else . end;

# Reserved words that open or continue a compound command run the next word as a
# command; `for`/`select` headers and `function NAME` name no program of their own.
def strip_wrappers:
  if length == 0 then .
  elif (.[0] | IN("!", "{", "do", "then", "else", "elif", "if", "while", "until")) then .[1:] | strip_wrappers
  elif (.[0] | IN("for", "select")) then []
  elif .[0] == "function" then .[2:] | strip_wrappers
  elif (.[0] | test("^[A-Za-z_][A-Za-z0-9_]*=")) then .[1:] | strip_wrappers
  elif (.[0] | basename_of) as $w | wrapper_value_options | has($w) then
    (.[0] | basename_of) as $w
    | .[1:] | skip_options(wrapper_value_options[$w])
    | if $w == "timeout" then .[1:] else . end
    | strip_wrappers
  else . end;

def operands: map(select(is_option | not));

def in_place_flag: any(.[]; test("^-[A-Za-z]*i|^--in-place"));

def destination:
  # cp/install/ln/rsync write only their destination: -t DIR, --target-directory=DIR,
  # or the last operand (`ln -s target` with one operand links into the cwd).
  . as $args
  | ([range(0; length) | select($args[.] == "-t") | $args[. + 1] // empty]
     + [$args[] | select(startswith("--target-directory=")) | sub("^--target-directory="; "")]) as $t
  | if ($t | length) > 0 then $t
    else (operands) as $ops
      | if ($ops | length) >= 2 then [$ops[-1]] elif ($ops | length) == 1 then ["."] else [] end
    end;

def git_read_only($sub; $rest):
  ["status", "diff", "log", "show", "blame", "annotate", "grep", "ls-files", "ls-tree",
   "ls-remote", "cat-file", "rev-parse", "rev-list", "describe", "shortlog", "reflog",
   "show-ref", "for-each-ref", "name-rev", "whatchanged", "help", "version", "merge-base",
   "cherry", "count-objects", "var", "check-ignore", "check-attr", "difftool", "fsck",
   "show-branch", "range-diff", "verify-commit", "verify-tag", "archive"] as $ro | ($sub | IN($ro[]))
  or ($sub == "branch" and ($rest | all(.[]; test("^-(a|r|v|vv|l|-list|-all|-remotes|-show-current|-contains|-merged|-no-merged|-points-at|-sort=.*|-format=.*|-verbose)$"))))
  or ($sub == "tag" and (($rest | length) == 0 or ($rest | any(.[]; . == "-l" or . == "--list"))))
  or ($sub == "stash" and (($rest[0] // "") | IN("list", "show")))
  or ($sub == "remote" and (($rest | length) == 0 or (($rest[0] // "") | IN("-v", "show", "get-url"))))
  or ($sub == "config" and ($rest | any(.[]; test("^--get|^--list$|^-l$"))))
  or ($sub == "worktree" and (($rest[0] // "") == "list"))
  or ($sub == "submodule" and (($rest | length) == 0 or (($rest[0] // "") | IN("status", "summary"))));

def jj_read_only($subs):
  ($subs[0] // "") as $s | ($subs[1] // "") as $t
  | (["status", "st", "log", "diff", "show", "files", "root", "help", "version", "evolog",
      "obslog", "interdiff", "cat"] as $ro | ($s | IN($ro[])))
    or ($s == "file" and ($t | IN("show", "list", "annotate", "search")))
    or (($s == "op" or $s == "operation") and ($t | IN("log", "show", "diff")))
    or ($s == "config" and ($t | IN("get", "list", "path")))
    or (($s == "bookmark" or $s == "branch" or $s == "tag") and ($t | IN("list", "l")))
    or ($s == "workspace" and ($t | IN("list", "root")))
    or ($s == "git" and ($t == "remote") and (($subs[2] // "") == "list"));

def git_actions($args):
  # Global options before the subcommand: -C DIR (cumulative), --work-tree[=]DIR,
  # --git-dir[=]DIR, -c KEY=VALUE; other flags are skipped.
  (reduce range(0; $args | length) as $i ({dir: "", skip: false, sub: null, at: null};
      if .sub != null or .skip then .skip = false
      elif $args[$i] == "-C" then .dir = (if .dir == "" then ($args[$i + 1] // "") else .dir + "/" + ($args[$i + 1] // "") end) | .skip = true
      elif $args[$i] == "--work-tree" then .dir = ($args[$i + 1] // "") | .skip = true
      elif ($args[$i] | startswith("--work-tree=")) then .dir = ($args[$i] | sub("^--work-tree="; ""))
      elif $args[$i] == "--git-dir" or $args[$i] == "-c" or $args[$i] == "--namespace" then .skip = true
      elif ($args[$i] | is_option) then .
      else .sub = $args[$i] | .at = $i end)) as $g
  | if $g.sub == null then empty
    else ($args[$g.at + 1:]) as $rest
      | if git_read_only($g.sub; $rest) then empty
        else ["r", $g.dir], ($rest | operands[] | ["ra", .]) end
    end;

def jj_actions($args):
  (reduce range(0; $args | length) as $i ({dir: "", skip: false, subs: []};
      if .skip then .skip = false
      elif $args[$i] == "-R" or $args[$i] == "--repository" then .dir = ($args[$i + 1] // "") | .skip = true
      elif ($args[$i] | startswith("--repository=")) then .dir = ($args[$i] | sub("^--repository="; ""))
      elif $args[$i] == "--at-op" or $args[$i] == "--at-operation" or $args[$i] == "--config" or $args[$i] == "--config-file" or $args[$i] == "--color" then .skip = true
      elif ($args[$i] | is_option) then .
      else .subs += [$args[$i]] end)) as $j
  | if ($j.subs | length) == 0 or jj_read_only($j.subs) then empty
    else ["r", $j.dir], ($j.subs[1:][] | ["ra", .]) end;

def mutating_program:
  ["rm", "rmdir", "unlink", "touch", "truncate", "shred", "mkdir", "mv", "chmod", "chown",
   "chgrp", "tee", "mkfifo", "mknod"];

def command_actions($depth):
  def segment_actions:
    (.redirs[] | select(startswith("/dev/") | not) | ["w", .]),
    ((.words | strip_wrappers) as $w
     | if ($w | length) == 0 then empty
       else ($w[0] | basename_of) as $prog | $w[1:] as $args
       | if $prog == "cd" then ["cd", ([$args[] | select(. == "-" or (is_option | not))] | .[0]) // $vars.HOME]
         elif $prog == "pushd" then ["pushd", ($args | operands | .[0]) // ""]
         elif $prog == "popd" then (if ($args | length) == 0 then ["popd"] else empty end)
         elif ($prog | IN("bash", "sh", "zsh", "dash", "ksh")) and $depth < 2 then
           ([range(0; $args | length) | select($args[.] | test("^-[A-Za-z]*c[A-Za-z]*$"))] | .[0]) as $c
           | if $c == null then empty
             else ["push"], (($args[$c + 1] // "") | command_actions($depth + 1)), ["pop"] end
         elif $prog == "eval" and $depth < 2 then $args | join(" ") | command_actions($depth + 1)
         elif ($prog | IN(mutating_program[])) then $args | operands[] | ["w", .]
         elif ($prog | IN("cp", "install", "ln", "rsync")) then $args | destination[] | ["w", .]
         elif ($prog | IN("sed", "gsed", "perl")) and ($args | in_place_flag) then $args | operands[] | ["w", .]
         elif $prog == "dd" then $args[] | select(startswith("of=")) | ["w", .[3:]]
         elif $prog == "patch" then
           ([range(0; $args | length) | select($args[.] == "-d") | $args[. + 1] // empty]
            + [$args[] | select(startswith("--directory=")) | sub("^--directory="; "")]) as $d
           | (if ($d | length) > 0 then $d[] else "." end | ["w", .]),
             ($args | operands[] | ["w", .])
         elif $prog == "find" then
           (any($args[]; . == "-delete")
            or ([range(0; $args | length) | select($args[.] | IN("-exec", "-execdir", "-ok", "-okdir"))
                 | ($args[. + 1] // "" | basename_of)]
                | any(.[]; . as $p | ($p | IN(mutating_program[])) or ($p | IN("cp", "install", "ln", "rsync", "sed", "perl"))))) as $writes
           | if $writes then
               ([foreach $args[] as $a ({stop: false, out: null};
                   if .stop or ($a | test("^[-(!]")) then .stop = true | .out = null else .out = $a end;
                   .out // empty)] | if length == 0 then ["."] else . end)[] | ["w", .]
             else empty end
         elif $prog == "git" then git_actions($args)
         elif $prog == "jj" then jj_actions($args)
         else empty end
       end);
  segments[]
  | if .mark != null then [.mark]
    else {words: (.words | map(unquote | expand_word)), redirs: (.redirs | map(unquote | expand_word))}
      | segment_actions
    end;

(.tool_input.command // "") | if type == "string" then . else tostring end
| command_actions(0)
| @tsv
