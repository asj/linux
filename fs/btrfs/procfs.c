// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Oracle.  All rights reserved.
 */

#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/btrfs_tree.h>
#include "ctree.h"
#include "volumes.h"
#include "rcu-string.h"
#include "block-group.h"
#include "space-info.h"
#include "procfs.h"

#define BPSL	256

#define BTRFS_PROC_PATH		"fs/btrfs"
#define BTRFS_PROC_DEVLIST	"devlist"
#define BTRFS_PROC_FSINFO	"fsinfo"
#define BTRFS_PROC_CHUNKLIST	"chunklist"
#define BTRFS_PROC_BGS		"blockgroups"

#define BALANCE_RUNNING
//#define OLD_PROC
//#define USE_ALLOC_LIST

#define NO_VOL_FLAGS
#define NO_CHUNK_LAYOUT
#define NO_READPOLICY
#define NO_READPOLICY_DYNAMIC_LATENCY
#define NO_DEVTYPE
#define NO_DEVTYPE_MIXED
#define NO_RENAME_OPENED_RW

struct proc_dir_entry	*btrfs_proc_root = NULL;

static void fs_state_to_str(struct btrfs_fs_info *fs_info, char *str)
{
	memset(str, 0, 256);
	if (test_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state))
		strcat(str, "|REMOUNTING");
	if (test_bit(BTRFS_FS_STATE_RO, &fs_info->fs_state))
		strcat(str, "|RO");
	if (test_bit(BTRFS_FS_STATE_TRANS_ABORTED, &fs_info->fs_state))
		strcat(str, "|TRANS_ABORTED");
	if (test_bit(BTRFS_FS_STATE_DEV_REPLACING, &fs_info->fs_state))
		strcat(str, "|REPLACING");
	if (test_bit(BTRFS_FS_STATE_DUMMY_FS_INFO, &fs_info->fs_state))
		strcat(str, "|DUMMY");
	if (test_bit(BTRFS_FS_STATE_NO_CSUMS, &fs_info->fs_state))
		strcat(str, "|NO_CSUMS");
	if (test_bit(BTRFS_FS_STATE_LOG_CLEANUP_ERROR, &fs_info->fs_state))
		strcat(str, "|LOG_CLEANUP_ERROR");
	strcat(str, ".");
}

static void fs_flags_to_str(struct btrfs_fs_info *fs_info, char *str)
{
	memset(str, 0, 256);
	if (test_bit(BTRFS_FS_CLOSING_START, &fs_info->flags))
		strcat(str, "|CLOSING_START");
	if (test_bit(BTRFS_FS_CLOSING_DONE, &fs_info->flags))
		strcat(str, "|CLOSING_DONE");
	if (test_bit(BTRFS_FS_LOG_RECOVERING, &fs_info->flags))
		strcat(str, "|RECOVERING");
#ifndef NO_RENAME_OPENED_RW
	if (test_bit(BTRFS_FS_OPENED_RW, &fs_info->flags))
		strcat(str, "|OPENED_RW");
#endif
	if (test_bit(BTRFS_FS_QUOTA_ENABLED, &fs_info->flags))
		strcat(str, "|QUOTA_ENABLED");
	if (test_bit(BTRFS_FS_UPDATE_UUID_TREE_GEN, &fs_info->flags))
		strcat(str, "|UPDATE_UUID_TREE_GEN");
	if (test_bit(BTRFS_FS_CREATING_FREE_SPACE_TREE, &fs_info->flags))
		strcat(str, "|FREE_SPACE_TREE");
	if (test_bit(BTRFS_FS_BTREE_ERR, &fs_info->flags))
		strcat(str, "|BTREE_ERR");
	if (test_bit(BTRFS_FS_LOG1_ERR, &fs_info->flags))
		strcat(str, "|LOG1_ERR");
	if (test_bit(BTRFS_FS_LOG2_ERR, &fs_info->flags))
		strcat(str, "|LOG2_ERR");
	if (test_bit(BTRFS_FS_QUOTA_OVERRIDE, &fs_info->flags))
		strcat(str, "|QUOTA_OVERRIDE");
	if (test_bit(BTRFS_FS_FROZEN, &fs_info->flags))
		strcat(str, "|FROZEN");
#ifdef BALANCE_RUNNING
	if (test_bit(BTRFS_FS_BALANCE_RUNNING, &fs_info->flags))
		strcat(str, "|BALANCE_RUNNING");
#else
	if (atomic_read(&fs_info->balance_running))
		strcat(str, "|BALANCE_RUNNING");
#endif
	if (atomic_read(&fs_info->balance_pause_req))
		strcat(str, "|BALANCE_PAUSEREQ");
	if (atomic_read(&fs_info->balance_cancel_req))
		strcat(str, "|BALANCE_CANCELREQ");
	strcat(str, ".");
}

static void balance_flags_to_str(u64 flags, char *str)
{
	if (BTRFS_BALANCE_DATA & flags)
		strcat(str, "|DATA");
	if (BTRFS_BALANCE_SYSTEM & flags)
		strcat(str, "|SYSTEM");
	if (BTRFS_BALANCE_METADATA & flags)
		strcat(str, "|METADATA");
	if (BTRFS_BALANCE_FORCE & flags)
		strcat(str, "|FORCE");
	if (BTRFS_BALANCE_RESUME & flags)
		strcat(str, "|RESUME");
}

char *bg_flags_to_str(u64 chunk_type, char *str)
{
	if (chunk_type & BTRFS_BLOCK_GROUP_RAID0)
		strcat(str, "|RAID0");
	if (chunk_type & BTRFS_BLOCK_GROUP_RAID1)
		strcat(str, "|RAID1");
	if (chunk_type & BTRFS_BLOCK_GROUP_RAID5)
		strcat(str, "|RAID5");
	if (chunk_type & BTRFS_BLOCK_GROUP_RAID6)
		strcat(str, "|RAID6");
	if (chunk_type & BTRFS_BLOCK_GROUP_DUP)
		strcat(str, "|DUP");
	if (chunk_type & BTRFS_BLOCK_GROUP_RAID10)
		strcat(str, "|RAID10");
	if (chunk_type & BTRFS_AVAIL_ALLOC_BIT_SINGLE)
		strcat(str, "|ALLOC_SINGLE");

	return str;
}

struct btrfs_bg_attr {
	const char name[10];
};

enum btrfs_bg_types {
	BTRFS_BG_SYSTEM,
	BTRFS_BG_MIXED,
	BTRFS_BG_DATA,
	BTRFS_BG_METADATA,
	BTRFS_NR_BG_TYPES
};

const struct btrfs_bg_attr btrfs_bg_type[BTRFS_NR_BG_TYPES] = {
	[BTRFS_BG_SYSTEM] =  {
		.name = "system",
	},
	[BTRFS_BG_MIXED] =  {
		.name = "mixed",
	},
	[BTRFS_BG_DATA] =  {
		.name = "data",
	},
	[BTRFS_BG_METADATA] =  {
		.name = "metadata",
	},
};

#if 0
static enum btrfs_bg_types btrfs_bg_type_index(u64 flags)
{
	if ((flags & BTRFS_BLOCK_GROUP_TYPE_MASK) ==
	    (BTRFS_BLOCK_GROUP_DATA|BTRFS_BLOCK_GROUP_METADATA))
		return BTRFS_BG_MIXED;
	if (flags & BTRFS_BLOCK_GROUP_DATA)
		return BTRFS_BG_DATA;
	if (flags & BTRFS_BLOCK_GROUP_METADATA)
		return BTRFS_BG_METADATA;
	return BTRFS_BG_SYSTEM;
}
#endif

static void balance_args_to_str(struct btrfs_balance_args *bargs, char *str,
				char *prefix)
{
	int ret = 0;

	ret = sprintf(str, "\tbalance_args.%s\t", prefix);
	str = str + ret;

	if (bargs->flags & BTRFS_BALANCE_ARGS_SOFT)
		strcat(str, "|SOFT");

	if (bargs->flags & BTRFS_BALANCE_ARGS_PROFILES) {
		strcat(str, "|profiles=");
		str = bg_flags_to_str(bargs->profiles, str);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_USAGE) {
		ret = sprintf(str, "|usage=%llu ", bargs->usage);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_USAGE_RANGE) {
		ret = sprintf(str, "|usage_min=%u usage_max=%u",
			      bargs->usage_min, bargs->usage_max);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_DEVID) {
		ret = sprintf(str, "|devid=%llu ", bargs->devid);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_DRANGE) {
		ret = sprintf(str, "|DRANGE pstart=%llu pend=%llu ",
			      bargs->pstart, bargs->pend);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_VRANGE) {
		ret = sprintf(str, "|VRANGE vstart=%llu vend %llu",
			      bargs->vstart, bargs->vend);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_LIMIT) {
		ret = sprintf(str, "|limit=%llu ", bargs->limit);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_LIMIT_RANGE) {
		ret = sprintf(str, "|limit_min=%u limit_max=%u",
			      bargs->limit_min, bargs->limit_max);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_STRIPES_RANGE) {
		ret = sprintf(str, "|stripes_min=%u stripes_max=%u ",
			bargs->stripes_min, bargs->stripes_max);
		str = str + ret;
	}

	if (bargs->flags & BTRFS_BALANCE_ARGS_CONVERT) {
		strcat(str, "|convert=");
		str = bg_flags_to_str(bargs->target, str);
	}
}

static void print_balance_args(struct btrfs_balance_args *bargs, char *prefix,
				struct seq_file *seq)
{
#define BTRFS_SEQ_PRINT3(plist, arg) \
	do { \
		snprintf(__str, BPSL, plist, arg);\
		seq_puts(seq, __str); \
	} while (0)
	char __str[BPSL];

	char tmp_str[BPSL];

	memset(tmp_str, '\0', 256);
	balance_args_to_str(bargs, tmp_str, prefix);
	BTRFS_SEQ_PRINT3("%s\n", tmp_str);
}

static void balance_progress_to_str(struct btrfs_balance_progress *bstat, char *str)
{
	int ret = 0;

	ret = sprintf(str, "expected=%llu ", bstat->expected);
	str = str + ret;
	ret = sprintf(str, "considered=%llu ", bstat->considered);
	str = str + ret;
	ret = sprintf(str, "completed=%llu ", bstat->completed);
}

static inline char *excl_ops_str(struct btrfs_fs_info *fs_info)
{
	char *str;

	switch (READ_ONCE(fs_info->exclusive_operation)) {
	case  BTRFS_EXCLOP_NONE:
		str = "none\n";
		break;
	case BTRFS_EXCLOP_BALANCE:
		str = "balance\n";
		break;
	case BTRFS_EXCLOP_DEV_ADD:
		str = "device add\n";
		break;
	case BTRFS_EXCLOP_DEV_REMOVE:
		str = "device remove\n";
		break;
	case BTRFS_EXCLOP_DEV_REPLACE:
		str = "device replace\n";
		break;
	case BTRFS_EXCLOP_RESIZE:
		str = "resize\n";
		break;
	case BTRFS_EXCLOP_SWAP_ACTIVATE:
		str = "swap activate\n";
		break;
	default:
		str = "UNKNOWN\n";
		break;
	}

	return str;
}

void btrfs_print_fsinfo(struct seq_file *seq)
{
	/* Btrfs Procfs String Len */
#define BTRFS_SEQ_PRINT2(plist, arg) \
	do { \
		snprintf(str, BPSL, plist, arg); \
		seq_puts(seq, str); \
	} while (0)

	char str[BPSL];
	struct list_head *cur_uuid;
	struct btrfs_fs_info *fs_info;
	struct btrfs_fs_devices *fs_devices;
	struct list_head *fs_uuids = btrfs_get_fs_uuids();

	seq_puts(seq, "\n#Its for debugging and experimental only, parameters may change without notice.\n\n");

	list_for_each(cur_uuid, fs_uuids) {
		char fs_str[256] = {0};

		fs_devices  = list_entry(cur_uuid, struct btrfs_fs_devices, fs_list);
		fs_info = fs_devices->fs_info;
		if (!fs_info)
			continue;

		BTRFS_SEQ_PRINT2("[fsid_sb: %pU]\n", fs_info->super_copy->fsid);
		BTRFS_SEQ_PRINT2("\tsb->s_uuid:\t\t%pUb\n", &fs_info->sb->s_uuid);
		BTRFS_SEQ_PRINT2("\tsb->s_bdev:\t\t%s\n", fs_info->sb->s_bdev ?
				 fs_info->sb->s_bdev->bd_disk->disk_name : "null");
		BTRFS_SEQ_PRINT2("\tlatest_bdev:\t\t%s\n",
				 fs_devices->latest_dev->bdev ?
				 fs_devices->latest_dev->bdev->bd_disk->disk_name : "null");

		BTRFS_SEQ_PRINT2("\tfs_error:\t\t%d\n", fs_info->fs_error);
		fs_state_to_str(fs_info, fs_str);
		BTRFS_SEQ_PRINT2("\tfs_state:\t\t%s\n", fs_str);

		fs_flags_to_str(fs_info, fs_str);
		BTRFS_SEQ_PRINT2("\tfs_flags:\t\t%s\n", fs_str);

		BTRFS_SEQ_PRINT2("\tmount_opt:\t\t%lx\n", fs_info->mount_opt);

		BTRFS_SEQ_PRINT2("\tsuper_copy->flags\t0x%llx\n",
				fs_info->super_copy->flags);
		BTRFS_SEQ_PRINT2("\tsuper_for_commit->flags\t0x%llx\n",
				fs_info->super_for_commit->flags);
		BTRFS_SEQ_PRINT2("\tnodesize\t\t%u\n", fs_info->nodesize);
		BTRFS_SEQ_PRINT2("\tsectorsize\t\t%u\n", fs_info->sectorsize);

		BTRFS_SEQ_PRINT2("\texclusive_operation\t\t%s\n", excl_ops_str(fs_info));

		if (fs_info->balance_ctl) {
			memset(fs_str, '\0', 256);
			balance_flags_to_str(fs_info->balance_ctl->flags, fs_str);
			BTRFS_SEQ_PRINT2("\tbalance_control\t\t%s\n", fs_str);

			if (fs_info->balance_ctl->flags & BTRFS_BALANCE_DATA)
				print_balance_args(&fs_info->balance_ctl->data, "data", seq);
			if (fs_info->balance_ctl->flags & BTRFS_BALANCE_METADATA)
				print_balance_args(&fs_info->balance_ctl->meta, "meta", seq);
			if (fs_info->balance_ctl->flags & BTRFS_BALANCE_SYSTEM)
				print_balance_args(&fs_info->balance_ctl->sys, "sys", seq);

			memset(fs_str, '\0', 256);
			balance_progress_to_str(&fs_info->balance_ctl->stat, fs_str);
			BTRFS_SEQ_PRINT2("\tbalance_progress\t%s\n", fs_str);

		} else {
			BTRFS_SEQ_PRINT2("\tbalance_control\t\t%s\n", "null");
		}

		BTRFS_SEQ_PRINT2("\tscrubs_running\t\t%d\n",
				 atomic_read(&fs_info->scrubs_running));
		BTRFS_SEQ_PRINT2("\tscrub_pause_req\t\t%d\n",
				 atomic_read(&fs_info->scrub_pause_req));
		BTRFS_SEQ_PRINT2("\tscrubs_paused\t\t%d\n",
				 atomic_read(&fs_info->scrubs_paused));
		BTRFS_SEQ_PRINT2("\tscrub_cancel_req\t\t%d\n",
				 atomic_read(&fs_info->scrub_cancel_req));

		BTRFS_SEQ_PRINT2("\tdev_replace.replace_state\t\t%llu\n",
				 fs_info->dev_replace.replace_state);
		BTRFS_SEQ_PRINT2("\tdev_replace.time start\t\t%lld\n",
				 fs_info->dev_replace.time_started);
		BTRFS_SEQ_PRINT2("\tdev_replace.time stopped\t%lld\n",
				 fs_info->dev_replace.time_stopped);
		BTRFS_SEQ_PRINT2("\tdev_replace.cursor_left\t\t%llu\n",
				 fs_info->dev_replace.cursor_left);
		BTRFS_SEQ_PRINT2("\tdev_replace.committed_cursor_left\t%llu\n",
				 fs_info->dev_replace.committed_cursor_left);
		BTRFS_SEQ_PRINT2("\tdev_replace.cursor_left_last_write_of_item\t%llu\n",
				 fs_info->dev_replace.cursor_left_last_write_of_item);
		BTRFS_SEQ_PRINT2("\tdev_replace.cursor_right\t\t%llu\n",
				 fs_info->dev_replace.cursor_right);
		BTRFS_SEQ_PRINT2("\tdev_replace.cont_reading_from_srcdev_mode\t%llu\n",
				 fs_info->dev_replace.cont_reading_from_srcdev_mode);
		BTRFS_SEQ_PRINT2("\tdev_replace.is_valid\t\t\t%d\n",
				 fs_info->dev_replace.is_valid);
		BTRFS_SEQ_PRINT2("\tdev_replace.item_needs_writeback\t%d\n",
				 fs_info->dev_replace.item_needs_writeback);
		BTRFS_SEQ_PRINT2("\tdev_replace.srcdev\t\t\t%p\n",
				 fs_info->dev_replace.srcdev);
		BTRFS_SEQ_PRINT2("\tdev_replace.tgtdev\t\t\t%p\n",
				 fs_info->dev_replace.tgtdev);
		BTRFS_SEQ_PRINT2("\tdev_replace.bio_counter.count\t\t%llu\n",
				 fs_info->dev_replace.bio_counter.count);
#ifndef NO_CHUNK_LAYOUT
		BTRFS_SEQ_PRINT2("\tchunk_layout data\t\t\t%d\n",
				 fs_info->chunk_layout_data);
		BTRFS_SEQ_PRINT2("\tchunk_layout metadata\t\t\t%d\n",
				 fs_info->chunk_layout_metadata);
#endif
	}
}

static void dev_state_to_str(struct btrfs_device *device, char *dev_state_str)
{
	if (test_bit(BTRFS_DEV_STATE_WRITEABLE, &device->dev_state))
		strcat(dev_state_str, "|WRITEABLE");
	if (test_bit(BTRFS_DEV_STATE_IN_FS_METADATA, &device->dev_state))
		strcat(dev_state_str, "|IN_FS_METADATA");
	if (test_bit(BTRFS_DEV_STATE_MISSING, &device->dev_state))
		strcat(dev_state_str, "|MISSING");
	if (test_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state))
		strcat(dev_state_str, "|REPLACE_TGT");
	if (test_bit(BTRFS_DEV_STATE_FLUSH_SENT, &device->dev_state))
		strcat(dev_state_str, "|FLUSH_SENT");
#ifndef NO_READPOLICY
	if (test_bit(BTRFS_DEV_STATE_READ_PREFERRED, &device->dev_state))
		strcat(dev_state_str, "|RD_PREFFRRED");
#endif
	if (device->dev_stats_valid)
		strcat(dev_state_str, "|dev_stats_valid");
}

#ifndef NO_VOL_FLAGS
static void vol_flags_to_str(struct btrfs_fs_devices *fs_devices, char *vol_flags)
{
	if (test_bit(BTRFS_VOL_FLAG_ROTATING, &fs_devices->vol_flags))
		strcat(vol_flags, "|ROTATING");
	if (test_bit(BTRFS_VOL_FLAG_SEEDING, &fs_devices->vol_flags))
		strcat(vol_flags, "|SEEDING");
	if (test_bit(BTRFS_VOL_FLAG_EXCL_OPS, &fs_devices->vol_flags))
		strcat(vol_flags, "|EXCL_OPS");
}
#endif

#define BTRFS_SEQ_PRINT(plist, arg) \
	do { \
		snprintf(str, BPSL, plist, arg); \
		if (sprt) { \
			if (seq) \
				seq_puts(seq, "\t"); \
		} \
		if (seq) \
			seq_puts(seq, str); \
		else \
			pr_debug("boilerplate: %s", str); \
	} while (0)

static void print_a_device(struct seq_file *seq, struct btrfs_device *device,
			   struct btrfs_fs_devices *sprt)
{
	char str[BPSL];
	char dev_state_str[256] = {0};

	BTRFS_SEQ_PRINT("\t[[UUID: %pU]]\n", device->uuid);
	BTRFS_SEQ_PRINT("\t\tdev_addr:\t%p\n", device);
	rcu_read_lock();
	BTRFS_SEQ_PRINT("\t\tdevice:\t\t%s\n",
			device->name ? rcu_str_deref(device->name) : "(null)");
	rcu_read_unlock();
	BTRFS_SEQ_PRINT("\t\tMAJ:MIN\t\t%u:", MAJOR(device->devt));
	BTRFS_SEQ_PRINT("%u\n", MINOR(device->devt));

	if (device->bdev) {
		BTRFS_SEQ_PRINT("\t\tMAJ:MIN bdev\t%u:",
						MAJOR((device->bdev)->bd_dev));
		BTRFS_SEQ_PRINT("%u\n", MINOR((device->bdev)->bd_dev));
	}

	BTRFS_SEQ_PRINT("\t\tdevid:\t\t%llu\n", device->devid);
	BTRFS_SEQ_PRINT("\t\tgeneration:\t%llu\n", device->generation);
	BTRFS_SEQ_PRINT("\t\ttotal_bytes:\t%llu\n", device->total_bytes);
	BTRFS_SEQ_PRINT("\t\tdev_totalbytes:\t%llu\n", device->disk_total_bytes);
	BTRFS_SEQ_PRINT("\t\tbytes_used:\t%llu\n", device->bytes_used);
	BTRFS_SEQ_PRINT("\t\ttype:\t\t%llu\n", device->type);
#ifndef NO_DEVTYPE
	BTRFS_SEQ_PRINT("\t\tdev_type:\t%u\n", device->dev_type);
#endif
	BTRFS_SEQ_PRINT("\t\tio_align:\t%u\n", device->io_align);
	BTRFS_SEQ_PRINT("\t\tio_width:\t%u\n", device->io_width);
	BTRFS_SEQ_PRINT("\t\tsector_size:\t%u\n", device->sector_size);
	dev_state_to_str(device, dev_state_str);
	if (strlen(dev_state_str) == 0)
		BTRFS_SEQ_PRINT("\t\tdev_state:\t0x%lx\n", device->dev_state);
	else
		BTRFS_SEQ_PRINT("\t\tdev_state:\t%s\n", dev_state_str);

	if (device->devid_kobj.state_initialized)
		BTRFS_SEQ_PRINT("\t\tdevid_kobj:\t%d\n", device->devid_kobj.state_initialized);
	else
		BTRFS_SEQ_PRINT("\t\tdevid_kobj:\t%s\n", "null");
#if 0
	BTRFS_SEQ_PRINT("\t\tbdev:\t\t%s\n", device->bdev ? "not_null":"null");
	if (device->bdev) {
		struct backing_dev_info *bdi = device->bdev->bd_bdi;

		BTRFS_SEQ_PRINT("\t\tbdi:\t\t%s\n", bdi ? "not_null" : "null");
		if (bdi) {
			struct bdi_writeback *wb = &bdi->wb;

			BTRFS_SEQ_PRINT("\t\twb:\t\t%s\n", wb ? "not_null" : "null");
			if (wb) {
				BTRFS_SEQ_PRINT("\t\twb congested flags:\t%lx\n",
						wb->congested);
				BTRFS_SEQ_PRINT("\t\twb write_bandwidth:\t%lx\n",
						wb->write_bandwidth);
			}
		}
	}
#endif
#ifndef NO_READPOLICY_DYNAMIC_LATENCY
	BTRFS_SEQ_PRINT("\t\tavg_read_latency:\t\t%llu\n", device->avg_read_latency);
#endif
}

static void print_a_fs_device(struct seq_file *seq, struct btrfs_fs_devices *fs_devices,
			      struct btrfs_fs_devices *sprt)
{
	char str[BPSL];
	struct btrfs_device *device = NULL;
	size_t sz = sizeof(*fs_devices);

	if (sprt)
		BTRFS_SEQ_PRINT("[[seed_fsid: %pU]]\n", fs_devices->fsid);
	else
		BTRFS_SEQ_PRINT("[fsid: %pU]\n", fs_devices->fsid);

	BTRFS_SEQ_PRINT("\tsize:\t\t\t%ld\n", sz);

	BTRFS_SEQ_PRINT("\tmetadata_uuid:\t\t%pU\n", fs_devices->metadata_uuid);

	if (sprt)
		BTRFS_SEQ_PRINT("\tsprout_fsid:\t\t%pU\n", sprt->fsid);

/*
 *	if (!list_is_last(&fs_devices->seed_list, &fs_devices->seed))
 *		seed = list_next_entry(&fs_device->seed, seed_list);
 *	seed = list_first_entry_or_null(fs_devices->seed_list.next,
 *					struct btrfs_fs_devices, seed_list);
 *	if (seed)
 *		BTRFS_SEQ_PRINT("\tseed_fsid:\t\t%pU\n", seed->fsid);
 */

	BTRFS_SEQ_PRINT("\tfs_devs_addr:\t\t%p\n", fs_devices);
	BTRFS_SEQ_PRINT("\tnum_devices:\t\t%llu\n", fs_devices->num_devices);
	BTRFS_SEQ_PRINT("\topen_devices:\t\t%llu\n", fs_devices->open_devices);
	BTRFS_SEQ_PRINT("\trw_devices:\t\t%llu\n", fs_devices->rw_devices);
	BTRFS_SEQ_PRINT("\tmissing_devices:\t%llu\n", fs_devices->missing_devices);
	BTRFS_SEQ_PRINT("\ttotal_rw_bytes:\t\t%llu\n", fs_devices->total_rw_bytes);
	BTRFS_SEQ_PRINT("\ttotal_devices:\t\t%llu\n", fs_devices->total_devices);
	BTRFS_SEQ_PRINT("\topened:\t\t\t%d\n", fs_devices->opened);
	BTRFS_SEQ_PRINT("\ttempfsid:\t\t\t%d\n", fs_devices->temp_fsid);
#ifndef NO_DEVTYPE_MIXED
	BTRFS_SEQ_PRINT("\tmixed_dev_types:\t%s\n",
			fs_devices->mixed_dev_types ? "True" : "False");
#endif
#ifndef NO_VOL_FLAGS
	vol_flags_to_str(fs_devices, vol_flags);
	BTRFS_SEQ_PRINT("\vol_flags:\\%s\n", vol_flags);
#else
	BTRFS_SEQ_PRINT("\tseeding:\t\t%d\n", fs_devices->seeding);
	BTRFS_SEQ_PRINT("\trotating:\t\t%d\n", fs_devices->rotating);
	BTRFS_SEQ_PRINT("\tdiscardable:\t\t%d\n", fs_devices->discardable);
//	BTRFS_SEQ_PRINT("\tfsid_change:\t\t%d\n", fs_devices->fsid_change);
#endif

#if 0
	BTRFS_SEQ_PRINT("\tfsid_kobj_state:\t%d\n", fs_devices->fsid_kobj.state_initialized);
	BTRFS_SEQ_PRINT("\tfsid_kobj_insysfs:\t%d\n", fs_devices->fsid_kobj.state_in_sysfs);

	if (fs_devices->devices_kobj) {
		BTRFS_SEQ_PRINT("\tkobj_state:\t\t%d\n",
				fs_devices->devices_kobj->state_initialized);
		BTRFS_SEQ_PRINT("\tkobj_insysfs:\t\t%d\n",
				fs_devices->devices_kobj->state_in_sysfs);
	} else {
		BTRFS_SEQ_PRINT("\tkobj_state:\t\t%s\n", "null");
		BTRFS_SEQ_PRINT("\tkobj_insysfs:\t\t%s\n", "null");
	}
#endif
	rcu_read_lock();
	BTRFS_SEQ_PRINT("\tlatest_dev:\t\t%s\n", fs_devices->latest_dev ?
			rcu_str_deref(fs_devices->latest_dev->name) : "NULL");
	rcu_read_unlock();
#ifndef NO_READPOLICY
	switch (fs_devices->read_policy) {
	case BTRFS_READ_POLICY_PID:
		BTRFS_SEQ_PRINT2("\tread_policy\t\t%s\n", "BTRFS_READ_POLICY_PID:");
		break;
	case BTRFS_READ_POLICY_DEVICE:
		list_for_each_entry(device, &fs_devices->devices, dev_list) {
			if (test_bit(BTRFS_DEV_STATE_READ_PREFERRED, &device->dev_state))
				BTRFS_SEQ_PRINT("%llu ", device->devid);
		}
		BTRFS_SEQ_PRINT("%s\n", " ");
		break;
	default:
		BTRFS_SEQ_PRINT2("\tread_policy\t%s\n", "unknown\n");
	}
#endif

	list_for_each_entry(device, &fs_devices->devices, dev_list) {
		print_a_device(seq, device, sprt);
	}

#ifdef USE_ALLOC_LIST
	/* print device from the alloc_list */
BTRFS_SEQ_PRINT("%s\n", "alloc_list");
	list_for_each_entry(device, &fs_devices->alloc_list, dev_alloc_list) {
		print_a_device(seq, device, sprt);
	}
#endif
}


void btrfs_print_devlist(struct seq_file *seq, struct btrfs_fs_devices *the_fs_devices)
{
	struct list_head *fs_uuids = btrfs_get_fs_uuids();
	struct list_head *cur_uuid;

	if (seq)
		seq_puts(seq, "\n#Its for debugging and experimental only, parameters may change without notice.\n\n");

	/* Todo: there must be better way than nested locks */
	list_for_each(cur_uuid, fs_uuids) {
		struct btrfs_fs_devices *fs_devices;
		struct btrfs_fs_devices *sprt = NULL; //sprout fs devices
		struct btrfs_fs_devices *seed = NULL; //seed fs devices
#ifndef NO_VOL_FLAGS
		char vol_flags[256] = {0};
#endif
		fs_devices  = list_entry(cur_uuid, struct btrfs_fs_devices, fs_list);

//		mutex_lock(&fs_devices->device_list_mutex);

		if (the_fs_devices) {
			if (the_fs_devices == fs_devices)
				print_a_fs_device(seq, fs_devices, sprt);
		} else {
			print_a_fs_device(seq, fs_devices, sprt);
		}

		sprt = fs_devices;
		list_for_each_entry(seed, &fs_devices->seed_list, seed_list) {
			if (the_fs_devices) {
				if (the_fs_devices == seed)
					print_a_fs_device(seq, seed, sprt);
			} else {
				print_a_fs_device(seq, seed, sprt);
			}
			sprt = seed;
		}
		if (seq)
			seq_puts(seq, "\n");

//		mutex_unlock(&fs_devices->device_list_mutex);
	}
}

#define bufsize 4096
char global_buf[bufsize];

char retstr[60];
int retstr_size = 60;

#if 0
inline int em_flag_to_str(unsigned long *flags)
{
	int ret = 0;

	memset(retstr, 0, retstr_size);

	if (test_bit(EXTENT_FLAG_PINNED, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "PINNED");
	if (test_bit(EXTENT_FLAG_COMPRESSED, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "COMPRESSED");
	if (test_bit(EXTENT_FLAG_PREALLOC, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "PREALLOC");
	if (test_bit(EXTENT_FLAG_LOGGING, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "LOGGING");
	if (test_bit(EXTENT_FLAG_FILLING, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "FILING");
	if (test_bit(EXTENT_FLAG_FS_MAPPING, flags))
		ret += snprintf(retstr + ret, retstr_size - ret, "%s|", "FS_MAPPING");

	if (ret)
		retstr[ret - 1] = '\0';

	return ret;
}

#define append_to_buf(fmt, arg) { \
	if (aptr >= bufsize) \
		printk("Boilerplate Error: bufsize %d too small %lu\n", \
			bufsize, aptr); \
	aptr += snprintf(global_buf + aptr, bufsize - aptr, fmt, arg); }


static char *btrfs_dump_chunklist(struct btrfs_fs_info *fs_info)
{
	struct extent_map_tree *map_tree = &fs_info->mapping_tree;
	struct extent_map *em;
	u64 next_start = 0;
	size_t aptr = 0;

	memset(global_buf, 0, bufsize);

	read_lock(&map_tree->lock);
	em = lookup_extent_mapping(map_tree, 0, (u64)-1);
	read_unlock(&map_tree->lock);
	/* No chunk at all? Return false anyway */
	if (!em)
		return ERR_PTR(-EINTR);

	append_to_buf("[fsid: %pU]\n", fs_info->fs_devices->fsid);
	while (em) {
		int i;
		struct map_lookup *map = em->map_lookup;

		append_to_buf("extent_map:%s\n", "");
		append_to_buf("start:\t\t%llu\n", em->start);
		append_to_buf("len:\t\t%llu\n", em->len);
		append_to_buf("mod_start:\t%llu\n", em->mod_start);
		append_to_buf("mod_len:\t%llu\n", em->mod_len);
		append_to_buf("orig_start:\t%llu\n", em->orig_start);
		append_to_buf("orig_block_len:\t%llu\n", em->orig_block_len);
		append_to_buf("ram_bytes:\t%llu\n", em->ram_bytes);
		append_to_buf("block_start:\t%llu\n", em->block_start);
		append_to_buf("block_len:\t%llu\n", em->block_len);
		append_to_buf("generication:\t%llu\n", em->generation);
		append_to_buf("flags:\t\t0x%lx", em->flags);
		//em_flag_to_str(&em->flags);
		//append_to_buf(" %s\n", retstr);
		append_to_buf("refcount:\t%u\n", refcount_read(&em->refs));
		append_to_buf("compress_type:\t%u\n\n", em->compress_type);

		append_to_buf("map_lookup:%s\n", "");
		append_to_buf("type:\t\t0x%llx", map->type);
		append_to_buf(" %s|",
			      btrfs_bg_type[btrfs_bg_type_index(map->type)].name);
		append_to_buf("%s\n", btrfs_bg_type_to_raid_name(map->type));
		append_to_buf("io_align:\t%d\n", map->io_align);
		append_to_buf("io_width:\t%d\n", map->io_width);
		//append_to_buf("stripe_len:\t%u\n", map->stripe_len);
		append_to_buf("num_stripes:\t%d\n", map->num_stripes);
		append_to_buf("sub_stripes:\t%d\n", map->sub_stripes);
		append_to_buf("verified_stripes:%d\n", map->verified_stripes);

		for (i = 0; i < map->num_stripes; i++) {
			append_to_buf("devid:\t\t%llu\n", map->stripes[i].dev->devid);
			append_to_buf("\tphysical:%llu\n", map->stripes[i].physical);
		}
		append_to_buf("-------------%s--------------\n", "x");

		next_start = extent_map_end(em);
		free_extent_map(em);
		read_lock(&map_tree->lock);
		em = lookup_extent_mapping(map_tree, next_start,
					   (u64)(-1) - next_start);
		read_unlock(&map_tree->lock);
	}

	return global_buf;
}

static int btrfs_chunklist_show(struct seq_file *seq, void *inode)
{
	char *buf;
	struct list_head *cur_uuid;
	struct btrfs_fs_info *fs_info;
	struct btrfs_fs_devices *fs_devices;
	struct list_head *fs_uuids = btrfs_get_fs_uuids();

	seq_puts(seq, "\n#Its Experimental, parameters may change without notice.\n\n");

	list_for_each(cur_uuid, fs_uuids) {
		fs_devices  = list_entry(cur_uuid, struct btrfs_fs_devices, fs_list);
		fs_info = fs_devices->fs_info;
		if (!fs_info)
			continue;

		buf = btrfs_dump_chunklist(fs_info);
		if (IS_ERR(buf))
			continue;

		seq_printf(seq, "%s", buf);
	}

	return 0;
}

#endif
static int btrfs_fsinfo_show(struct seq_file *seq, void *offset)
{
	btrfs_print_fsinfo(seq);
	return 0;
}

static int btrfs_devlist_show(struct seq_file *seq, void *offset)
{
	btrfs_print_devlist(seq, NULL);
	return 0;
}

#if 0
static char *btrfs_dump_bgs(struct btrfs_fs_info *fs_info)
{
	struct extent_map_tree *map_tree = &fs_info->mapping_tree;
	struct extent_map *em;
	struct btrfs_block_group *cache = NULL;
	u64 next_start = 0;
	size_t aptr = 0;

	memset(global_buf, 0, bufsize);

	append_to_buf("[fsid: %pU]\n", fs_info->fs_devices->fsid);

	read_lock(&map_tree->lock);
	em = lookup_extent_mapping(map_tree, 0, (u64)-1);
	read_unlock(&map_tree->lock);
	if (!em)
		return ERR_PTR(-EINTR);

	while (em) {
		struct btrfs_space_info *si;

		cache = btrfs_lookup_block_group(fs_info, em->start);
		if (!cache)
			break;
		si = cache->space_info;

		append_to_buf("bg_start:\t%llu\n", cache->start);
		append_to_buf("len:\t\t%llu\n", cache->length);
		append_to_buf("readonly:\t%d\n", cache->ro);

		append_to_buf("%s\n", " space_info");
		append_to_buf("\tdisk_used:\t%llu\n", si->disk_used);
		append_to_buf("\tdisk_total:\t%llu\n", si->disk_total);
		append_to_buf("%s\n", " ");

		btrfs_put_block_group(cache);

		next_start = extent_map_end(em);
		free_extent_map(em);

		read_lock(&map_tree->lock);
		em = lookup_extent_mapping(map_tree, next_start,
					   (u64)(-1) - next_start);
		read_unlock(&map_tree->lock);
	}

	return global_buf;
}

static int btrfs_bgs_show(struct seq_file *seq, void *inode)
{
	char *buf;
	struct list_head *cur_uuid;
	struct btrfs_fs_info *fs_info;
	struct btrfs_fs_devices *fs_devices;
	struct list_head *fs_uuids = btrfs_get_fs_uuids();

	seq_puts(seq, "\n#Its Experimental, parameters may change without notice.\n\n");

	list_for_each(cur_uuid, fs_uuids) {
		fs_devices  = list_entry(cur_uuid, struct btrfs_fs_devices, fs_list);
		fs_info = fs_devices->fs_info;
		if (!fs_info)
			continue;

		buf = btrfs_dump_bgs(fs_info);
		if (IS_ERR(buf))
			continue;

		seq_printf(seq, "%s", buf);
	}

	return 0;
}
#endif

static int btrfs_seq_fsinfo_open(struct inode *inode, struct file *file)
{
	return single_open(file, btrfs_fsinfo_show, inode->i_private);
}

static int btrfs_seq_devlist_open(struct inode *inode, struct file *file)
{
	return single_open(file, btrfs_devlist_show, inode->i_private);
}

#if 0
static int btrfs_seq_chunklist_open(struct inode *inode, struct file *file)
{
	return single_open(file, btrfs_chunklist_show, inode->i_private);
}

static int btrfs_seq_bgs_open(struct inode *inode, struct file *file)
{
	return single_open(file, btrfs_bgs_show, inode->i_private);
}
#endif

#ifdef OLD_PROC
static const struct file_operations btrfs_seq_devlist_fops = {
	.owner   = THIS_MODULE,
	.open    = btrfs_seq_devlist_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops btrfs_seq_devlist_fops = {
	.proc_open    = btrfs_seq_devlist_open,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
};
#endif

#ifdef OLD_PROC
static const struct file_operations btrfs_seq_fsinfo_fops = {
	.owner   = THIS_MODULE,
	.open    = btrfs_seq_fsinfo_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops btrfs_seq_fsinfo_fops = {
	.proc_open    = btrfs_seq_fsinfo_open,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
};
#endif

#if 0
#ifdef OLD_PROC
static const struct file_operations btrfs_seq_chunklist_fops = {
	.owner	 = THIS_MODULE,
	.open	 = btrfs_seq_chunklist_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops btrfs_seq_chunklist_fops = {
	.proc_open	= btrfs_seq_chunklist_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif

#ifdef OLD_PROC
static const struct file_operations btrfs_seq_bgs_fops = {
	.owner	 = THIS_MODULE,
	.open	 = btrfs_seq_bgs_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops btrfs_seq_bgs_fops = {
	.proc_open	= btrfs_seq_bgs_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif
#endif

int __init btrfs_init_procfs(void)
{
	btrfs_proc_root = proc_mkdir(BTRFS_PROC_PATH, NULL);
	if (btrfs_proc_root) {
		proc_create_data(BTRFS_PROC_DEVLIST, 0444, btrfs_proc_root,
					&btrfs_seq_devlist_fops, NULL);
		proc_create_data(BTRFS_PROC_FSINFO, 0444, btrfs_proc_root,
					&btrfs_seq_fsinfo_fops, NULL);
#if 0
		proc_create_data(BTRFS_PROC_CHUNKLIST, 0444, btrfs_proc_root,
					&btrfs_seq_chunklist_fops, NULL);
		proc_create_data(BTRFS_PROC_BGS, 0444, btrfs_proc_root,
					&btrfs_seq_bgs_fops, NULL);
#endif
	}
	return 0;
}

void __cold btrfs_exit_procfs(void)
{
	if (btrfs_proc_root) {
		remove_proc_entry(BTRFS_PROC_DEVLIST, btrfs_proc_root);
		remove_proc_entry(BTRFS_PROC_FSINFO, btrfs_proc_root);
#if 0
		remove_proc_entry(BTRFS_PROC_CHUNKLIST, btrfs_proc_root);
		remove_proc_entry(BTRFS_PROC_BGS, btrfs_proc_root);
#endif
	}
	remove_proc_entry(BTRFS_PROC_PATH, NULL);
	btrfs_proc_root = NULL;
}
