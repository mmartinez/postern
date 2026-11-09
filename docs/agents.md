# Agent enrollment

New configurations require named proxy identities. Enroll a client and launch
its explicitly selected recipient with `postern agent add NAME --exec PROGRAM
[ARGS...]`. Keys stay in memory and reach only the child environment; configuration
stores only a verifier. `postern agent list` prints names only. A hash-only remote
enrollment artifact can be selected with `--enrollment-out PATH --proxy URL`.

Missing or invalid proxy authentication gets a generic 407 before credential
resolution or upstream access. Configure the recipient's public CA trust before
launch. Legacy bootstrap snippets cannot enroll authenticated clients. Processes
that can inspect the child environment can impersonate that identity; deployments
must enforce egress containment. Loss of the in-memory key requires re-enrollment.
