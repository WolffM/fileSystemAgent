rule TestStringDetection {
    meta:
        description = "Test rule that matches a known test marker string"
        severity = "medium"
        author = "FileSystemAgent E2E Tests"
    strings:
        $test_marker = "FSA_TEST_MARKER_STRING_FOR_YARA_DETECTION"
    condition:
        $test_marker
}
