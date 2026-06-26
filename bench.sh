{
  echo "Benchmark Run"
  echo "============================================"
  echo "Date:     $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Commit:   $(git rev-parse --short=12 HEAD)"
  echo "Branch:   $(git branch --show-current 2>/dev/null || echo 'detached')"
  echo "Go:       $(go version)"
  echo "============================================"
  echo ""
  go test -bench=. -run=^$ -benchmem "$@"
} | tee "benchmarks/benchmark_$(date +%Y%m%d_%H%M%S).txt"

# -count=3