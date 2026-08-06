/*
 * Copyright 2026 The HuaTuo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.ArrayList;
import java.util.List;

public final class JavaOOMStackFixture {
    private static volatile long sink;

    private JavaOOMStackFixture() {}

    private static long hotMethod(long value) {
        return value * 31 + 7;
    }

    private static void exhaustMemory() throws Exception {
        List<byte[]> allocations = new ArrayList<>();
        Thread.sleep(3_000);
        while (true) {
            allocations.add(new byte[4 * 1024 * 1024]);
            sink = hotMethod(allocations.size());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("oom")) {
            exhaustMemory();
            return;
        }
        long deadline = System.nanoTime() + Long.parseLong(args[0]) * 1_000_000_000L;
        long value = 1;
        while (System.nanoTime() < deadline) {
            for (int index = 0; index < 100_000; index++) {
                value = hotMethod(value);
            }
            sink = value;
            Thread.sleep(1);
        }
    }
}
