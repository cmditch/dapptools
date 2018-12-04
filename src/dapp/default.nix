{ lib, stdenv, fetchFromGitHub, makeWrapper, glibcLocales
, bats, coreutils, git, gnused, hevm, jshon, jq
, nix, nodejs, perl, seth, shellcheck, solc }:

stdenv.mkDerivation rec {
  name = "dapp-${version}";
  version = "0.9.0";
  src = ./.;

  nativeBuildInputs = [ bats makeWrapper shellcheck coreutils ];
  buildPhase = "true";
  doCheck = true;
  checkPhase = let kek = ''
    wrapProgram make --prefix PATH : "$out/bin/dapp"
  ''; in "${kek} test";
  makeFlags = ["prefix=$(out)"];
  postInstall = let path = lib.makeBinPath [
    coreutils git gnused hevm jshon jq nix nodejs perl seth solc
  ]; in ''
    wrapProgram "$out/bin/dapp" --prefix PATH : "${path}" \
      ${if glibcLocales != null then
        "--set LOCALE_ARCHIVE \"${glibcLocales}\"/lib/locale/locale-archive"
        else ""}
  '';

  meta = {
    description = "Simple tool for creating Ethereum-based dapps";
    homepage = https://github.com/dapphub/dapptools/src/dapp/;
    maintainers = [stdenv.lib.maintainers.dbrock];
    license = lib.licenses.gpl3;
    inherit version;
  };
}
