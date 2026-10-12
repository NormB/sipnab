// A program with exactly one leak, for .github/workflows/memcheck.yml to run
// under Valgrind before it judges sipnab. If memcheck does not report this
// block as definitely lost, the job's clean verdicts mean nothing, and the job
// fails instead of passing.
//
// The allocation goes through black_box: LLVM may delete an allocation nothing
// reads, and the 2026-10-10 review saw it do so at -O.
fn main() {
    let v: Vec<u8> = std::hint::black_box(vec![7u8; 4096]);
    let p = v.as_ptr();
    std::mem::forget(v);
    println!("{:p}", std::hint::black_box(p));
}
