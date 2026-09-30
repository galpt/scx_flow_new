// SPDX-License-Identifier: GPL-2.0
/*
 * vEB maps for the flow core.
 *
 * Holds summary, clusters, counts, pid rows, root.
 * Summary tracks live high parts. Clusters track live low parts.
 * Counts track live tasks per key. Pid rows track the key per task.
 * Root caches least, greatest, presence. All maps use fixed
 * ARRAY except pid rows which use HASH capped at task bound. Sizes
 * stay fixed so the verifier sees bounded access. Updates use atomic
 * compare and swap so concurrent CPUs stay consistent with fail
 * closed drops on faults. Policy lives in the daemon with order in
 * the core.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
struct veb_root {
	u32 min;
	u32 max;
	u32 has;
	u32 pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u64);
} veb_summary SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} veb_clusters SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__type(key, u32);
	__type(value, u32);
} veb_counts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct veb_root);
} veb_root SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, u32);
} veb_pid SEC(".maps");
