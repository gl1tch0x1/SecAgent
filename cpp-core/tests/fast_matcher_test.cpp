#include "fast_matcher.hpp"

int main() {
    using SecAgentCore::FastMatcher;
    if (!FastMatcher::scan_signature("SQL syntax error", "sql.*error")) return 1;
    if (FastMatcher::scan_signature("normal response", "sql.*error")) return 2;
    if (!FastMatcher::scan_first("token=abc", {"missing", "token"}).matched) return 3;
    if (FastMatcher::scan_all("normal", {"sql", "token"}).size() != 0) return 4;
    return 0;
}
