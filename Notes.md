# Type converting between native and managed code

| native   | managed   | remark                                                                            |
| ------   | -------   | ------                                                                            |
| `size_t` | `UIntPtr` | [discussion](https://stackoverflow.com/questions/772531/net-equivalent-of-size-t) |

Compile:

    msbuild Capstone.NETCore.csproj /p:AllowUnsafeBlocks=true

