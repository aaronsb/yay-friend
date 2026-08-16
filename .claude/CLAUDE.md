# yay-friend

## Releasing

`aaronsb/arch-repo` publishes this project. It reads `./PKGBUILD-git` from the
default branch, builds it in a clean container, lints with namcap, signs, and
pushes to the AUR (`yay-friend-git`) and the `[aaronsb]` pacman repository.

This repository publishes a **VCS package only**. There is no versioned package
and no tarball: `yay-friend-git` builds from the default branch at HEAD, so the
standing obligation is that **main always builds**.

That also means there is no release to cut. arch-repo publishes when the recipe
changes and at no other time — so a packaging change *is* the release:

```bash
make package                 # clean-chroot build + namcap; fails on a namcap error
git push                     # arch-repo picks up the recipe change and republishes
```

Nothing here talks to the AUR. There is no `aur` target and no publish script:
two writers to one AUR ref is how a PKGBUILD and its `.SRCINFO` drift apart.

### Fields arch-repo owns

Do not maintain `pkgrel`, and do not commit a `.SRCINFO` — arch-repo overwrites
both. `pkgver` belongs to `pkgver()`, which derives it from `git describe` at
build time; never hardcode a base version there.

### Two things specific to this recipe

`make package` points `source=` at this checkout rather than at GitHub. A VCS
recipe has no tarball to archive from `HEAD`, so without that the dry run would
test whatever is already pushed instead of what is in front of you.

It also drops `yay` from the scratch copy. `yay` is itself an AUR package, so a
clean chroot cannot resolve it, and makepkg has no per-dependency escape — `-d`
skips the lot and takes `git` and `go` with it. It stays in the real `depends()`;
removing it would lie to whoever installs this.

`git` belongs in `depends()` and **not** also in `makedepends()`. namcap warns
in both directions — absent, "VCS source PKGBUILD needs additional makedepends
'git'"; present in both, "Make dependency (git) already included as dependency".
`depends()` alone is the arrangement that builds clean.

The full contract: https://github.com/aaronsb/arch-repo/blob/main/docs/packaging-contract.md
