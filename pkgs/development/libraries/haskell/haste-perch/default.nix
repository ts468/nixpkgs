# This file was auto-generated by cabal2nix. Please do NOT edit manually!

{ cabal, hastePackages, transformers }:

cabal.mkDerivation (self: {
  pname = "haste-perch";
  version = "0.1.0.3";
  sha256 = "1ad7kv47kq0sav49qnqdk76blk44sgjvk1zgn5k2bqvfnr26641j";
  buildDepends = [ hastePackages.haste transformers ];
  meta = {
    homepage = "https://github.com/agocorona/haste-perch";
    description = "Create, navigate and modify the DOM tree with composable syntax, with the haste compiler";
    license = self.stdenv.lib.licenses.gpl3;
    platforms = self.ghc.meta.platforms;
    maintainers = with self.stdenv.lib.maintainers; [ tomberek ];
  };
})
