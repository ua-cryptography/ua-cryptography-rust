/// Which table of DSTU 4145-2002, Appendix Г a recommended curve comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveBasis {
    /// Table Г.1: polynomial basis, m ∈ {163, 167, 173, 179, 191, 233, 257, 307, 367, 431}.
    Polynomial,
    /// Table Г.2: optimal normal basis, m ∈ {173, 179, 191, 233, 431}.
    OptimalNormal,
}
