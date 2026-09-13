# Repository instructions

The only permitted author and public attribution identity is Nick Seal
<32712898+blisspixel@users.noreply.github.com>, GitHub username blisspixel.
Do not add Codex, Claude, Anthropic, OpenAI, ChatGPT, Copilot, other assistant,
model, vendor, tool, or coauthor credits anywhere in public repository content.
This includes commit messages, PR titles and bodies, release notes, annotated tag
messages, documentation, README files, images, and UI text. Do not add attribution
trailers, signatures, footers, badges, or negative disclaimers such as "not by"
that name these tools. Do not add Co-Authored-By or similar trailers.
Do not use emojis or em dashes. Keep documentation current and tidy.
Preserve third-party copyright, license, NOTICE, and other legal attribution.
These rules never authorize removing or rewriting required legal notices.
Instruction files may name the prohibited credits to define this policy.

Enable the local commit guard in both sealr and sealr-validation checkouts with
`git config core.hooksPath .githooks`. The hook must have its executable Git mode.
Run `python scripts/verify_attribution.py --ci` before publication. Check prepared
PR, release, or tag text with
`python scripts/verify_attribution.py --text-file <path>`.
Apply these checks automatically without waiting for human approval.
