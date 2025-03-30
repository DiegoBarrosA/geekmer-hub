{
  description = "Java Spring Development with Maven";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.jdk17
            pkgs.maven
            pkgs.git
            pkgs.gnumake
            pkgs.bashInteractive
          ];
          JAVA_HOME = "${pkgs.jdk17}";
          M2_HOME = "${pkgs.maven}";
          PATH = "${pkgs.maven}/bin:${pkgs.jdk17}/bin:$PATH";
        };
      });
}
