// Copyright 2026 The HuaTuo Authors
// Licensed under the Apache License, Version 2.0.

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class HuatuoSnapshotFixture {
    static final class SmallPayload {
        final byte[] payload = new byte[256];
        final String kind = "small";
    }

    static final class LargePayload {
        final byte[] payload = new byte[256 * 1024];
        final String kind = "large";
    }

    // The mixed profile deliberately allocates classes in separate phases.
    // A sampler which only learns classes from an initial heap prefix can look
    // accurate on the default uniform fixture while completely missing the
    // warm and cold phases below.
    static final class HotPayload {
        final long a = 1;
        final long b = 2;
        final long c = 3;
        final long d = 4;
    }

    static final class WarmPayload {
        final byte[] payload = new byte[128];
    }

    static final class ColdPayload {
        // Keep the cold class itself diagnostically meaningful. Referenced
        // arrays are exercised separately by WarmPayload and the filler phases;
        // attributing a referenced 2KiB array to a tiny wrapper's shallow count
        // would test the wrong quantity in a class histogram.
        final long a0 = 0, a1 = 1, a2 = 2, a3 = 3;
        final long a4 = 4, a5 = 5, a6 = 6, a7 = 7;
        final long a8 = 8, a9 = 9, a10 = 10, a11 = 11;
        final long a12 = 12, a13 = 13, a14 = 14, a15 = 15;
    }

    private static final List<Object> RETAINED =
        Collections.synchronizedList(new ArrayList<Object>());

    public static void main(String[] args) throws Exception {
        final int workers = envInt("HUATUO_FIXTURE_WORKERS", 4);
        if ("mixed".equals(System.getenv("HUATUO_FIXTURE_MODE"))) {
            allocateMixed(workers);
            // Keep allocation phases spatially distinct. A forced full GC can
            // compact them into the uniform layout this profile is meant to
            // avoid.
            System.out.println("READY objects=" + RETAINED.size());
            System.out.flush();
            Thread.sleep(60000);
            return;
        }
        final int small = envInt("HUATUO_FIXTURE_SMALL_OBJECTS", 50000);
        final int large = envInt("HUATUO_FIXTURE_LARGE_OBJECTS", 128);
        Thread[] threads = new Thread[workers];
        for (int worker = 0; worker < workers; worker++) {
            threads[worker] = new Thread(() -> {
                for (int index = 0; index < small / workers; index++) {
                    RETAINED.add(new SmallPayload());
                }
                for (int index = 0; index < large / workers; index++) {
                    RETAINED.add(new LargePayload());
                }
            });
            threads[worker].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        System.gc();
        System.out.println("READY objects=" + RETAINED.size());
        System.out.flush();
        if ("1".equals(System.getenv("HUATUO_FIXTURE_OOM"))) {
            while (true) {
				byte[] value = new byte[8 * 1024 * 1024];
				for (int offset = 0; offset < value.length; offset += 4096) {
					value[offset] = (byte) offset;
				}
				RETAINED.add(value);
                Thread.sleep(10);
            }
        }
        Thread.sleep(60000);
    }

    private static void allocateMixed(int workers) throws Exception {
		if ("interleaved".equals(System.getenv("HUATUO_FIXTURE_JAVA_LAYOUT"))) {
			allocateInterleaved(workers,
				envInt("HUATUO_FIXTURE_HOT_OBJECTS", 700000),
				envInt("HUATUO_FIXTURE_WARM_OBJECTS", 200000),
				envInt("HUATUO_FIXTURE_COLD_OBJECTS", 100000));
			allocatePhase(workers, envInt("HUATUO_FIXTURE_FILLER_OBJECTS", 2048), 3);
			allocatePhase(workers, envInt("HUATUO_FIXTURE_HUMONGOUS_OBJECTS", 32), 4);
			return;
		}
        allocatePhase(workers, envInt("HUATUO_FIXTURE_HOT_OBJECTS", 700000), 0);
        allocatePhase(workers, envInt("HUATUO_FIXTURE_FILLER_OBJECTS", 2048), 3);
        allocatePhase(workers, envInt("HUATUO_FIXTURE_WARM_OBJECTS", 200000), 1);
        allocatePhase(workers, envInt("HUATUO_FIXTURE_FILLER_OBJECTS", 2048), 3);
        allocatePhase(workers, envInt("HUATUO_FIXTURE_COLD_OBJECTS", 100000), 2);
        allocatePhase(workers, envInt("HUATUO_FIXTURE_HUMONGOUS_OBJECTS", 32), 4);
    }

	private static void allocateInterleaved(int workers, int hot, int warm,
			int cold) throws Exception {
		Thread[] threads = new Thread[workers];
		for (int worker = 0; worker < workers; worker++) {
			final int workerIndex = worker;
			threads[worker] = new Thread(() -> {
				int[] targets = {
					hot * (workerIndex + 1) / workers - hot * workerIndex / workers,
					warm * (workerIndex + 1) / workers - warm * workerIndex / workers,
					cold * (workerIndex + 1) / workers - cold * workerIndex / workers,
				};
				int[] allocated = new int[targets.length];
				int total = targets[0] + targets[1] + targets[2];
				for (int index = 0; index < total; index++) {
					int kind = nextInterleavedKind(allocated, targets);
					allocated[kind]++;
					switch (kind) {
					case 0:
						RETAINED.add(new HotPayload());
						break;
					case 1:
						RETAINED.add(new WarmPayload());
						break;
					default:
						RETAINED.add(new ColdPayload());
						break;
					}
				}
			});
			threads[worker].start();
		}
		for (Thread thread : threads) {
			thread.join();
		}
	}

	private static int nextInterleavedKind(int[] allocated, int[] targets) {
		int selected = -1;
		for (int kind = 0; kind < targets.length; kind++) {
			if (allocated[kind] >= targets[kind]) {
				continue;
			}
			if (selected < 0 ||
					(long) allocated[kind] * targets[selected] <
					(long) allocated[selected] * targets[kind]) {
				selected = kind;
			}
		}
		return selected;
	}

    private static void allocatePhase(int workers, int count, int kind)
            throws Exception {
        Thread[] threads = new Thread[workers];
        for (int worker = 0; worker < workers; worker++) {
            final int workerIndex = worker;
            threads[worker] = new Thread(() -> {
                int begin = count * workerIndex / workers;
                int end = count * (workerIndex + 1) / workers;
                for (int index = begin; index < end; index++) {
                    switch (kind) {
                    case 0:
                        RETAINED.add(new HotPayload());
                        break;
                    case 1:
                        RETAINED.add(new WarmPayload());
                        break;
                    case 2:
                        RETAINED.add(new ColdPayload());
                        break;
                    case 3:
                        RETAINED.add(new byte[128 * 1024]);
                        break;
                    default:
                        RETAINED.add(new byte[2 * 1024 * 1024]);
                        break;
                    }
                }
            });
            threads[worker].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
    }

    private static int envInt(String name, int fallback) {
        String value = System.getenv(name);
        if (value == null) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : fallback;
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
