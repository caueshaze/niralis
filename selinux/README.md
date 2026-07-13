# Niralis SELinux policy

`niralis_t` is a dedicated display-manager domain. The privileged daemon,
worker and session child use `niralis_exec_t`; the test-only
`niralis-session-probe` is deliberately not labelled by this policy because it
is not executed in the production session lifecycle.

## openSUSE prerequisites

```sh
sudo zypper install selinux-policy-devel policycoreutils-devel checkpolicy
```

## Build and install

```sh
make -C selinux
sudo semodule -i selinux/niralis.pp
sudo python3 selinux/manage_default_contexts.py install
sudo restorecon -Rv /usr/local/sbin/niralisd /usr/libexec/niralis-session-worker /usr/libexec/niralis-session-child /etc/niralis /run/niralis
sudo systemctl restart niralisd
```

The managed `default_contexts` row is required for `pam_selinux` to calculate
the final account context from `system_r:niralis_t:s0`. The installer changes
only that exact row and refuses a conflicting manual row.

## Reversal

```sh
sudo python3 selinux/manage_default_contexts.py uninstall
sudo semodule -r niralis
sudo restorecon -Rv /usr/local/sbin/niralisd /usr/libexec/niralis-session-worker /usr/libexec/niralis-session-child /usr/libexec/niralis-session-probe
```
