/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Oracle.  All rights reserved.
 */

void __cold btrfs_exit_procfs(void);
int __init btrfs_init_procfs(void);
void btrfs_print_fsinfo(struct seq_file *seq);
void btrfs_print_devlist(struct seq_file *seq, struct btrfs_fs_devices *the_fs_devices);
char *bg_flags_to_str(u64 chunk_type, char *str);
