(function() {var implementors = {
"arithmetic":[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"arithmetic/struct.VirtualPolynomial.html\" title=\"struct arithmetic::VirtualPolynomial\">VirtualPolynomial</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"arithmetic/struct.VPAuxInfo.html\" title=\"struct arithmetic::VPAuxInfo\">VPAuxInfo</a>&lt;F&gt;"]],
"hyperplonk":[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"hyperplonk/prelude/struct.WitnessColumn.html\" title=\"struct hyperplonk::prelude::WitnessColumn\">WitnessColumn</a>&lt;F&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"hyperplonk/prelude/struct.CustomizedGates.html\" title=\"struct hyperplonk::prelude::CustomizedGates\">CustomizedGates</a>"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"hyperplonk/prelude/struct.SelectorColumn.html\" title=\"struct hyperplonk::prelude::SelectorColumn\">SelectorColumn</a>&lt;F&gt;"]],
"subroutines":[["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.UnivariateVerifierParam.html\" title=\"struct subroutines::pcs::prelude::UnivariateVerifierParam\">UnivariateVerifierParam</a>&lt;E&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/poly_iop/struct.PolyIOP.html\" title=\"struct subroutines::poly_iop::PolyIOP\">PolyIOP</a>&lt;F&gt;"],["impl&lt;E, PCS&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.BatchProof.html\" title=\"struct subroutines::pcs::prelude::BatchProof\">BatchProof</a>&lt;E, PCS&gt;<div class=\"where\">where\n    E: Pairing + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    PCS: <a class=\"trait\" href=\"subroutines/pcs/trait.PolynomialCommitmentScheme.html\" title=\"trait subroutines::pcs::PolynomialCommitmentScheme\">PolynomialCommitmentScheme</a>&lt;E&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    E::ScalarField: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    PCS::<a class=\"associatedtype\" href=\"subroutines/pcs/trait.PolynomialCommitmentScheme.html#associatedtype.Proof\" title=\"type subroutines::pcs::PolynomialCommitmentScheme::Proof\">Proof</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/poly_iop/prelude/struct.IOPProof.html\" title=\"struct subroutines::poly_iop::prelude::IOPProof\">IOPProof</a>&lt;F&gt;"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.UnivariateKzgProof.html\" title=\"struct subroutines::pcs::prelude::UnivariateKzgProof\">UnivariateKzgProof</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.UnivariateUniversalParams.html\" title=\"struct subroutines::pcs::prelude::UnivariateUniversalParams\">UnivariateUniversalParams</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    E::G2Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.MultilinearUniversalParams.html\" title=\"struct subroutines::pcs::prelude::MultilinearUniversalParams\">MultilinearUniversalParams</a>&lt;E&gt;<div class=\"where\">where\n    E::G2Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.MultilinearKzgProof.html\" title=\"struct subroutines::pcs::prelude::MultilinearKzgProof\">MultilinearKzgProof</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.MultilinearProverParam.html\" title=\"struct subroutines::pcs::prelude::MultilinearProverParam\">MultilinearProverParam</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    E::G2Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.Commitment.html\" title=\"struct subroutines::pcs::prelude::Commitment\">Commitment</a>&lt;E&gt;"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.MultilinearVerifierParam.html\" title=\"struct subroutines::pcs::prelude::MultilinearVerifierParam\">MultilinearVerifierParam</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    E::G2Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;C: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + AffineRepr&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subroutines/pcs/prelude/struct.UnivariateProverParam.html\" title=\"struct subroutines::pcs::prelude::UnivariateProverParam\">UnivariateProverParam</a>&lt;C&gt;"]],
"transcript":[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"transcript/struct.IOPTranscript.html\" title=\"struct transcript::IOPTranscript\">IOPTranscript</a>&lt;F&gt;"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()