# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import glob
from sos.report.plugins import Plugin, PluginOpt, IndependentPlugin, CosPlugin


JOURNAL_SINCE_LONG_DESC = (
    "Bounds the journalctl text capture by passing the value to "
    "`journalctl --since`, which accepts any systemd.time(7) "
    "expression (e.g. '-7days', '-24hours', '2 hours ago', "
    "'yesterday', '2026-04-19', '2026-04-19 08:00:00'). Use "
    "'all' (or leave empty) for no bound. Plugin default 'all', "
    "overridden to '-7days' by the bundled conf files. See "
    "`man systemd.time` and `man journalctl`."
)


class LogsBase(Plugin):

    short_desc = 'System logs'

    plugin_name = "logs"
    profiles = ('system', 'hardware', 'storage')

    option_list = [
        PluginOpt(name="journal-since", default="all", val_type=str,
                  desc=("journalctl --since value, e.g. '-7days', "
                        "or 'all' for no bound"),
                  long_desc=JOURNAL_SINCE_LONG_DESC)
    ]

    def setup(self):
        rsyslog = 'etc/rsyslog.conf'
        confs = ['/etc/syslog.conf', rsyslog]
        logs = []

        if self.path_exists(rsyslog):
            with open(self.path_join(rsyslog), 'r', encoding='UTF-8') as conf:
                for line in conf.readlines():
                    if line.startswith('$IncludeConfig'):
                        confs += glob.glob(line.split()[1])

        for conf in confs:
            if not self.path_exists(self.path_join(conf)):
                continue
            config = self.path_join(conf)
            logs += self.do_regex_find_all(r"^\S+\s+(-?\/.*$)\s+", config)

        for i in logs:
            if i.startswith("-"):
                i = i[1:]
            if self.path_isfile(i):
                self.add_copy_spec(i)

        self.add_copy_spec([
            "/etc/syslog.conf",
            "/etc/rsyslog.conf",
            "/etc/rsyslog.d",
            "/var/log/boot.log",
            "/var/log/installer",
            "/var/log/messages*",
            "/var/log/secure*",
            "/var/log/udev",
            "/var/log/dist-upgrade",
            "/var/log/auth.log",
        ])

        self.add_cmd_output("journalctl --disk-usage")
        self.add_dir_listing('/var/log', recursive=True)

        since_raw = (self.get_option("journal-since") or "").strip()
        since_arg = (None if since_raw.lower() in ("", "all") else since_raw)

        # collect journal logs if:
        # - there is some data present, either persistent or runtime only
        # - systemd-journald service exists
        # otherwise fallback to collecting few well known logfiles directly
        journal = any(self.path_exists(self.path_join(p, "log/journal/"))
                      for p in ["/var", "/run"])
        if journal and self.is_service("systemd-journald"):
            self.add_journal(tags=['journal_full', 'journal_all'],
                             priority=100, since=since_arg)
            self.add_journal(boot="this", tags='journal_since_boot',
                             since=since_arg)
            self.add_journal(boot="last", tags='journal_last_boot',
                             since=since_arg)
            if self.get_option("all_logs"):
                self.add_copy_spec([
                    "/var/log/journal/*",
                    "/run/log/journal/*"
                ])

        self.add_copy_spec([
            "/var/log/syslog*",
            "/var/log/kern.log*",
            "/var/log/auth.log*",
        ])

    def postproc(self):
        self.do_path_regex_sub(
            r"/etc/rsyslog*",
            r"(ActionLibdbiPassword |pwd=)(.*)",
            r"\1[********]"
        )


class IndependentLogs(LogsBase, IndependentPlugin):
    """
    This plugin will collect logs traditionally considered to be "system" logs,
    meaning those such as /var/log/messages, rsyslog, and journals that are
    not limited to unit-specific entries.

    Note that the --since option will apply to journal collections by this
    plugin as well as the typical application to log files. Most users can
    expect typical journal collections to include the "full" journal, as well
    as journals limited to this boot and the previous boot.
    """

    plugin_name = "logs"
    profiles = ('system', 'hardware', 'storage')


class CosLogs(LogsBase, CosPlugin):
    option_list = LogsBase.option_list + [
        PluginOpt(name="log-days", default=3,
                  desc="the number of days logs to collect")
    ]

    def setup(self):
        super().setup()
        if self.get_option("all_logs"):
            self.add_cmd_output("journalctl -o export")
        else:
            days = self.get_option("log-days", 3)
            self.add_journal(since=f"-{days}days")

# vim: set et ts=4 sw=4 :
