# Niralis SELinux policy

`niralis_t` is a dedicated display-manager domain. The privileged daemon,
worker, session child, and post-exec session probe use `niralis_exec_t` before
the probe applies PAM's pending final user context and execs the compositor.
The systemd `setpriv` wrapper starts in `unconfined_service_t`, but its exec of
the dedicated Niralis entrypoint transitions immediately into `niralis_t`.

## openSUSE prerequisites

```sh
sudo zypper install selinux-policy-devel policycoreutils-devel checkpolicy
```

## Build and install

```sh
make -C selinux
sudo semodule -i selinux/niralis.pp
sudo python3 selinux/manage_default_contexts.py install
sudo install -d -o root -g root -m 0700 /var/lib/niralis/recovery
sudo restorecon -Rv /usr/bin/niralisd /usr/sbin/niralisd /usr/libexec/niralis-session-worker /usr/libexec/niralis-session-child /usr/libexec/niralis-session-probe /etc/niralis /run/niralis /var/lib/niralis
sudo systemctl restart niralisd
```

The managed `default_contexts` row is required for `pam_selinux` to calculate
the final account context from `system_r:niralis_t:s0`. The installer changes
only that exact row and refuses a conflicting manual row.

## Reversal

```sh
sudo python3 selinux/manage_default_contexts.py uninstall
sudo semodule -r niralis
sudo restorecon -Rv /usr/bin/niralisd /usr/sbin/niralisd /usr/libexec/niralis-session-worker /usr/libexec/niralis-session-child /usr/libexec/niralis-session-probe /var/lib/niralis
```
