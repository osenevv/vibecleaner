# Plan: remove the slop

## Scope

`vibecleaner` takes a repo an LLM wrote and deletes the residue. What remains is the job the repo already described, in the words and the behavior it already had.

Slop is a default the model reached for. A reader who has seen LLM output can point at it, and the repo's job does not need it. It sits in three places, and the same test covers all three: the thing is specific to this repo, or the run deletes it.

- **Code.** A success that did not happen. A stub, a swallowed failure, a debug leftover, a comment that narrates the edit, a dead private, a backup copy, a pass-through, a duplicated body, a type that exists to silence the checker.
- **Words.** A sentence that could sit on another product unchanged. Chatbot residue, puffery, a label that names a different action than the handler, a number the repo never computed.
- **The screen and the terminal.** Template chrome, a control that does nothing, a stack of equal actions, lorem, a help line that does not name the arguments, a slow command that is silent, an error path that prints success.

A library has code and text. A CLI has the terminal as well. A web app has the page. The model that wrote the repo does not matter. Python, TypeScript, and a page are the proof. A further language is another parser in front of the same tells.

A repair deletes the residue, reconnects the action the repo already names, and rewrites a sentence so it says a fact the repo already had. Name, price, numbers, URLs, and the outputs of the real functions are copied into a fact table before any rewrite and have to survive it. The patch is a span the detector marked. The writer never receives the whole tree. The patch writer is whichever editor or API is already available. The re-scan decides whether the patch stays.

A repair adds nothing the repo never claimed: no feature, no metric, no customer, no second product area.

## Left out of this plan

Secrets, missing auth, row-level security, prompt injection, and client-trusted prices stay on `scan`. Launch checks stay on `preflight`. Tax, a live card charge, DNS, deliverability, and registrar 2FA stay listed and unclaimed.

The page instruction is five skills, in workflow order: ground, words, page, motion, check. Ground reads the product and a real reference. Words rewrites strings against the fact table. Page sets structure and states. Motion sets animation. Check reviews the result. A rule lives in one skill. A page is accepted when check is clean and the earlier skills still hold.

Tests the model wrote do not decide the run. The planted behavior and the re-scan do. A test that only asserts the fake goes out with the fake.

## Done when

Three trees pass. Two are fixtures this plan describes. The third is frozen before any new rule, and no rule is edited to suit it.

`benchmarks/slop/app` is a web app. The handler returns success without doing the thing the button names. The page is a stock template: a blue-to-purple gradient hero, glass on every surface, one pill radius and a large shadow on every block, a dot-grid background, emoji standing in for icons, three identical feature cards, more than one primary button, Inter as the only type decision. The flow is the success screenshot and nothing else: no loading, empty, or error state, an unlabeled field, a validation error that wipes the input, a control that does nothing, overflow at a phone width. Copy is residue from more than one model family. A paragraph in the hero stays true if the product name is swapped for another.

`benchmarks/slop/app/holdout.html` is a different template: a centered stack of six equal buttons, a focus trap, lorem in the labels. It shares no color, no gradient, and no phrase with the first page.

`benchmarks/slop/cli` is a command with no screen. Help is residue and does not name the arguments. The error path swallows the failure and prints success. A slow path prints nothing until it exits. A holdout stub returns a constant, never reads its input, and avoids every phrase the stub list names.

`benchmarks/slop/blind` is a tree this plan does not describe. It is committed first. Its labels name the residue and the lookalikes. Rules and fixtures may change. That tree and its labels may not.

Lookalikes stay in every tree: a catch that logs, an exported helper, a fenced quotation of a tic, a labeled field, a sentence that states the price, a comment that states a constraint the code hides, a shadow on a popover, a retry that ends in an error.

After one run on each fixture:

- The primary action returns the claimed result. The app's button does the operation the label names, and two submits leave one record. The CLI prints the planted output and exits non-zero on the planted bad input. The holdout stub is gone.
- The slop score is 100. The second check, the one that does not use the phrase lists, is clean on the holdout page, the holdout dialect, and the holdout stub.
- Words still contain the fact table and name the next action. A rewrite that adds a fact or drops the price is rejected. The primary control's label is the handler's action.
- The first view shows the product, one fact from the table, and one primary action, and that action is the repaired handler. Invalid input keeps what was typed and names the field. An empty result says what to do next. While the request is in flight the page shows pending and does not show the result. A failure says what to do and leaves the record unchanged. The page holds at a phone width. Both pages pass. A page with the chrome scraped off and no fact of its own still fails.
- On the CLI, `--help` names the command and its arguments, a bad input prints the field and the fix, a slow command prints that it is working, and success prints the result.
- Lookalikes are still present.
- A second run changes no file.

The blind tree is scored and left unedited until both fixtures are idempotent. Then one fix run is recorded. A miss becomes a general tell, written so the fixtures would have caught it too. A tell that only matches the blind tree is thrown out.

`fix` on this repository changes nothing, and the self-scan still prints `VIBECLEANER: PASS`.

## How a run removes it

Three passes. A pass re-checks its surface before the next starts. A patch that fails its check is dropped and the file stays as it was.

1. **Code.** Apply the span edits the detector can prove: delete the debug statement, the tic comment, the unused private, the unused backup; unwrap a catch that only rethrows; inline a pass-through; collapse a duplicate only when free names bind the same way. Then one diff per remaining stub or fake success. A stub is a success path that returns a constant without reading the input it claims to use. Accept the diff only when a re-scan clears that finding, the primary action returns the claimed result, and tests, config, and public signatures are intact.
2. **Text.** Run ground, then words. Ground writes the fact table. Words rewrites residue in docs, in-product strings, help, empty states, errors, and control labels. Accept the rewrite only when every fact is still there, no new fact appeared, the next action is named, the label matches the handler, and the prose scan is clean on the holdout dialect.
3. **Surface.** On a page, run page, then motion, then check. Page removes template structure: a technique on every block, a repeated card whose only change is the title, a hero with no fact, more than one primary action, a control with no handler, a focus trap, placeholder labels, overflow at a phone width. It restores the states of the one action: pending, empty, error, kept input. Motion sets animation. Check reviews the files those steps changed. Accept the diff only when check is clean at both widths, the first view still shows one fact and one action, and the code and text scans are still clean. A CLI or a library records this pass as not applicable.

The writer is the host it was launched from, else `claude`, `codex`, or `agy` on `PATH`, else a local model already running, else an API key already in the environment. With none of those, the proven code edits still apply and the report names the missing writer.

## Steps

### 1. Freeze the blind tree

Copy a repo this plan does not describe into `benchmarks/slop/blind`. Label the residue and the lookalikes. Commit that pair before any new rule.

Check: the labels exist, and a test fails if that tree or its labels change.

### 2. Fixtures that fail for the right reason

Add the app, the holdout page, and the CLI. The runner executes the primary action, scans code, scans copy, and records the structural tells at both widths.

Check: the runner names a costume success, an interchangeable paragraph, a structural template tell, the phone overflow, and the holdout stub. The holdout page is flagged. Lookalikes are not.

### 3. Code

Ship the proven span edits, then the structural stub.

Check: the app's button does the named operation and two submits leave one record. The CLI prints the planted output and exits non-zero on bad input. The holdout stub is gone. A patch that deletes a test is rejected. A catch that logs is still there.

### 4. Text

Extract facts, rewrite, re-scan. Cover help, errors, empty text, control labels, and a paragraph that names no fact.

Check: name and price survive. The next action is still stated. The primary control's label is the handler's action. An added testimonial or metric is rejected. The interchangeable paragraph is gone. A fenced quotation of a tic remains.

### 5. Surface

Run page, then motion, then check, on both pages. Words has already run.

Check: both pages are clean at desktop width and at phone width. The first view has the product, one fact, and one action. Pending, empty, error, and kept input hold. A page that only had its chrome removed still fails. The CLI help, error, slow path, and success line pass. Code and text scans stay clean.

### 6. The command

`vibecleaner fix` runs code, then text, then the surface. Exit 0 only when the fixture bar holds. Exit 1 writes the remaining residue. A second run changes no file. The same command prints the blind score beside the fixture result.

Check: both fixtures exit 0 and the second run is empty. The blind score is recorded. `fix` on this repository changes nothing.

## Left unclaimed

Tax, a live card charge, DNS, deliverability, and registrar 2FA stay in the report as not checked. The command does not invent a vendor account or a passing result for a check it did not run. Security findings stay on `scan`.
