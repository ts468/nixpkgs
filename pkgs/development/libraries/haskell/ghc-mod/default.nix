# This file was auto-generated by cabal2nix. Please do NOT edit manually!

{ cabal, async, Cabal, convertible, deepseq, djinnGhc, doctest
, emacs, filepath, ghcPaths, ghcSybUtils, haskellSrcExts, hlint
, hspec, ioChoice, makeWrapper, monadControl, monadJournal, mtl
, split, syb, text, time, transformers, transformersBase
}:

cabal.mkDerivation (self: {
  pname = "ghc-mod";
  version = "5.1.0.2";
  sha256 = "0jdni0n5qzz0ncaa3ja4b6vcfykbl7swiafak4wyvm9izssjh8ra";
  isLibrary = true;
  isExecutable = true;
  wrapExecutables = true;
  buildDepends = [
    async Cabal convertible deepseq djinnGhc filepath ghcPaths
    ghcSybUtils haskellSrcExts hlint ioChoice monadControl monadJournal
    mtl split syb text time transformers transformersBase
  ];
  testDepends = [
    Cabal convertible deepseq djinnGhc doctest filepath ghcPaths
    ghcSybUtils haskellSrcExts hlint hspec ioChoice monadControl
    monadJournal mtl split syb text time transformers transformersBase
  ];
  buildTools = [ emacs makeWrapper ];
  doCheck = false;
  configureFlags = "--datasubdir=${self.pname}-${self.version}";
  postInstall = ''
    cd $out/share/$pname-$version
    make
    rm Makefile
    cd ..
    ensureDir "$out/share/emacs"
    mv $pname-$version emacs/site-lisp
  '';
  meta = {
    homepage = "http://www.mew.org/~kazu/proj/ghc-mod/";
    description = "Happy Haskell Programming";
    license = self.stdenv.lib.licenses.bsd3;
    platforms = self.ghc.meta.platforms;
    maintainers = with self.stdenv.lib.maintainers; [
      andres bluescreen303 ocharles
    ];
  };
})
