<?php
require_once __DIR__ . '/cidrscan.php';
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIDRScan Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }

        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        h1,
        h2 {
            color: #333;
        }

        .success {
            color: #28a745;
            background-color: #d4edda;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid #c3e6cb;
        }

        .error {
            color: #dc3545;
            background-color: #f8d7da;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid #f5c6cb;
        }

        .info {
            color: #0c5460;
            background-color: #d1ecf1;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid #bee5eb;
        }

        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #e9ecef;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        th,
        td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        th {
            background-color: #f8f9fa;
        }

        .test-section {
            margin-bottom: 30px;
        }
    </style>
</head>

<body>
    <h1>🔍 CIDRScan</h1>
    <div class="info">
        <strong>About:</strong> CIDRScan‑rs is a zero-GC, wait-free LPM engine for firewalls, abuse filters, and geo
        fences. Cross-process shared memory, per-prefix TTLs, O(log W) reads via atomic pointer walks. C ABI included.
        No threads. No surprises. Just fast.
    </div>

    <?php function displayResult($title, $result, $isError = false)
    {
        $class = $isError ? 'error' : 'success';
        echo "<div class='$class'><strong>$title:</strong> " . htmlspecialchars($result) . "</div>\n";
    }

    function displayBooleanResult($title, $success, $successMessage, $failureMessage)
    {
        if ($success) {
            displayResult($title, $successMessage);
        } else {
            displayResult($title, $failureMessage, true);
        }
    }

    function displayInfo($message)
    {
        echo "<div class='info'>" . htmlspecialchars($message) . "</div>\n";
    }

    try {
        echo "<div class='container'>\n";
        echo "<h2>🚀 Step 1: Initialize CIDR Scanner</h2>\n";

        // Create a new CIDR scanner instance
        $handle = cidr_open("demo_scanner", 10000);
        displayResult("Scanner Created", "Handle ID: $handle");

        // Check initial capacity
        $capacity = cidr_available_capacity($handle);
        displayResult("Available Capacity", "$capacity entries");

        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>📝 Step 2: Insert Network Ranges</h2>\n";
        displayInfo("Adding various network ranges with tags for demonstration");

        // Sample network ranges to insert
        $networks = [
            ['cidr' => '192.168.1.0/24', 'ttl' => 3600, 'tag' => 'Private-LAN'],
            ['cidr' => '10.0.0.0/8', 'ttl' => 7200, 'tag' => 'RFC1918-ClassA'],
            ['cidr' => '172.16.0.0/12', 'ttl' => 7200, 'tag' => 'RFC1918-ClassB'],
            ['cidr' => '203.0.113.0/24', 'ttl' => 1800, 'tag' => 'TEST-NET-3'],
            ['cidr' => '8.8.8.0/24', 'ttl' => 86400, 'tag' => 'Google-DNS'],
            ['cidr' => '1.1.1.0/24', 'ttl' => 86400, 'tag' => 'Cloudflare-DNS'],
            ['cidr' => '127.0.0.0/8', 'ttl' => 3600, 'tag' => 'Loopback'],
            ['cidr' => '169.254.0.0/16', 'ttl' => 3600, 'tag' => 'Link-Local'],
        ];
        echo "<table>\n";
        echo "<tr><th>CIDR</th><th>TTL</th><th>Tag</th><th>Status</th></tr>\n";

        $insertCount = 0;
        $failCount = 0;

        foreach ($networks as $network) {
            try {
                $success = cidr_insert($handle, $network['cidr'], $network['ttl'], $network['tag']);
                if ($success) {
                    $status = "✅ Inserted";
                    $insertCount++;
                } else {
                    $status = "❌ Insert failed";
                    $failCount++;
                }
            } catch (Exception $e) {
                $status = "❌ Error: " . $e->getMessage();
                $failCount++;
            }

            echo "<tr>";
            echo "<td>" . htmlspecialchars($network['cidr']) . "</td>";
            echo "<td>" . htmlspecialchars($network['ttl']) . "</td>";
            echo "<td>" . htmlspecialchars($network['tag']) . "</td>";
            echo "<td>" . htmlspecialchars($status) . "</td>";
            echo "</tr>\n";
        }
        echo "</table>\n";

        displayResult("Insert Summary", "Successfully inserted: $insertCount, Failed: $failCount");

        $newCapacity = cidr_available_capacity($handle);
        displayResult("Remaining Capacity", ($capacity - $newCapacity) . " entries used, $newCapacity remaining");
        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>🔍 Step 3: Longest Prefix Match (LPM) Lookups</h2>\n";
        // Test IP addresses
        $testIPs = [
            '192.168.1.100',    // Should match 192.168.1.0/24
            '10.0.0.1',         // Should match 10.0.0.0/8
            '172.16.5.10',      // Should match 172.16.0.0/12
            '8.8.8.8',          // Should match 8.8.8.0/24
            '1.1.1.1',          // Should match 1.1.1.0/24
            '127.0.0.1',        // Should match 127.0.0.0/8
            '169.254.1.1',      // Should match 169.254.0.0/16
            '203.0.113.50',     // Should match 203.0.113.0/24
            '4.4.4.4',          // Should not match any range
            '192.168.2.1',      // Should not match (different subnet)
        ];

        echo "<table>\n";
        echo "<tr><th>IP Address</th><th>Found</th><th>Matched CIDR</th><th>Tag</th></tr>\n";

        foreach ($testIPs as $ip) {
            $found = cidr_lookup($handle, $ip);

            if ($found) {
                $match = cidr_lookup_full($handle, $ip);
                if ($match) {
                    $matchedCidr = $match->getCidrString();
                    $tag = $match->getTag() ?? 'No tag';
                    $foundIcon = "✅ Yes";
                } else {
                    $matchedCidr = "Error getting match details";
                    $tag = "-";
                    $foundIcon = "⚠️ Found but no details";
                }
            } else {
                $matchedCidr = "-";
                $tag = "-";
                $foundIcon = "❌ No";
            }

            echo "<tr>";
            echo "<td><code>" . htmlspecialchars($ip) . "</code></td>";
            echo "<td>" . htmlspecialchars($foundIcon) . "</td>";
            echo "<td>" . htmlspecialchars($matchedCidr) . "</td>";
            echo "<td>" . htmlspecialchars($tag) . "</td>";
            echo "</tr>\n";
        }
        echo "</table>\n";

        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>🗑️ Step 4: Delete Operations</h2>\n";
        displayInfo("Testing deletion of network ranges");        // Test deletion
        $deleteTarget = '203.0.113.0/24';
        try {
            $deleteSuccess = cidr_delete($handle, $deleteTarget);
            displayBooleanResult(
                "Deletion",
                $deleteSuccess,
                "Successfully deleted $deleteTarget",
                "Failed to delete $deleteTarget"
            );

            if ($deleteSuccess) {
                // Verify deletion
                $stillFound = cidr_lookup($handle, '203.0.113.50');
                if (!$stillFound) {
                    displayResult("Verification", "Confirmed: $deleteTarget no longer matches IP 203.0.113.50");
                } else {
                    displayResult("Verification", "Warning: $deleteTarget still matches", true);
                }
            }
        } catch (Exception $e) {
            displayResult("Deletion Error", $e->getMessage(), true);
        }

        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>📊 Step 5: Performance Test</h2>\n";
        displayInfo("Testing lookup performance with multiple operations");

        $testCount = 1000;
        $testIP = '192.168.1.50';

        $startTime = microtime(true);
        for ($i = 0; $i < $testCount; $i++) {
            cidr_lookup($handle, $testIP);
        }
        $endTime = microtime(true);

        $totalTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
        $avgTime = $totalTime / $testCount;

        echo "<table>\n";
        echo "<tr><th>Metric</th><th>Value</th></tr>\n";
        echo "<tr><td>Total Lookups</td><td>" . number_format($testCount) . "</td></tr>\n";
        echo "<tr><td>Total Time</td><td>" . number_format($totalTime, 2) . " ms</td></tr>\n";
        echo "<tr><td>Average Time per Lookup</td><td>" . number_format($avgTime, 4) . " ms</td></tr>\n";
        echo "<tr><td>Lookups per Second</td><td>" . number_format($testCount / ($totalTime / 1000), 0) . "</td></tr>\n";
        echo "</table>\n";
        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>🔧 Step 6: Additional Operations</h2>\n";
        displayInfo("Testing resize and clear operations");

        try {
            // Test resize operation
            $currentCapacity = cidr_available_capacity($handle);
            $newCapacity = $currentCapacity + 5000;
            displayInfo("Attempting to resize capacity from current available to $newCapacity total");
            $resizeSuccess = cidr_resize($handle, $newCapacity);
            displayBooleanResult(
                "Resize",
                $resizeSuccess,
                "Successfully resized scanner capacity",
                "Failed to resize scanner capacity"
            );

            if ($resizeSuccess) {
                $updatedCapacity = cidr_available_capacity($handle);
                displayResult("New Capacity", "$updatedCapacity entries available");
            }

            // Test clear operation
            displayInfo("Testing clear operation (removes all entries)");
            $clearSuccess = cidr_clear($handle);
            displayBooleanResult(
                "Clear",
                $clearSuccess,
                "Successfully cleared all entries",
                "Failed to clear entries"
            );

            if ($clearSuccess) {
                $clearedCapacity = cidr_available_capacity($handle);
                displayResult("Capacity After Clear", "$clearedCapacity entries available");

                // Verify that lookups no longer work
                $testAfterClear = cidr_lookup($handle, '192.168.1.100');
                if (!$testAfterClear) {
                    displayResult("Clear Verification", "Confirmed: No entries found after clear operation");
                } else {
                    displayResult("Clear Verification", "Warning: Entries still found after clear", true);
                }
            }

        } catch (Exception $e) {
            displayResult("Additional Operations Error", $e->getMessage(), true);
        }

        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>🧹 Step 7: Cleanup Operations</h2>\n";// Test other operations
        try {
            displayInfo("Testing flush operation");
            $flushSuccess = cidr_flush($handle);
            displayBooleanResult(
                "Flush",
                $flushSuccess,
                "Successfully flushed data to storage",
                "Failed to flush data to storage"
            );

            $finalCapacity = cidr_available_capacity($handle);
            displayResult("Final Capacity Check", "$finalCapacity entries available");

            displayInfo("Closing scanner handle");
            $closeSuccess = cidr_close($handle);
            displayBooleanResult(
                "Close",
                $closeSuccess,
                "Scanner closed successfully",
                "Failed to close scanner properly"
            );

        } catch (Exception $e) {
            displayResult("Cleanup Error", $e->getMessage(), true);
        }
        echo "</div>\n";

        echo "<div class='container'>\n";
        echo "<h2>💥 Step 8: Force Destroy Test</h2>\n";
        displayInfo("Testing force destroy operation (cleanup any lingering resources)");

        try {
            $destroySuccess = cidr_force_destroy("demo_scanner");
            displayBooleanResult(
                "Force Destroy",
                $destroySuccess,
                "Successfully force-destroyed scanner resources",
                "Force destroy operation returned false (may not be needed)"
            );
        } catch (Exception $e) {
            displayResult("Force Destroy Error", $e->getMessage(), true);
        }

        echo "</div>\n";

    } catch (Exception $e) {
        echo "<div class='container'>\n";
        echo "<div class='error'><strong>Fatal Error:</strong> " . htmlspecialchars($e->getMessage()) . "</div>\n";
        echo "</div>\n";
    }

    ?>
    <footer style="text-align: center; margin-top: 40px; color: #666;">
        <p>CIDR Scanner Demo - Powered by cidrscan-rs Rust library</p>
        <p>Run with: <code>php -S localhost:8000</code></p>
    </footer>
</body>

</html>