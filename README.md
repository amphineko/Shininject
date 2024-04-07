## Usages

### Generate a Mono library

```log
$ mcs /target:library /out:Shininject.dll Inject.cs
```

### Recover PE files (a.k.a. DLLs) from memory dumps

```log
PS > Get-Item .\*.bin | ForEach-Object { python repack.py $_ }
```
