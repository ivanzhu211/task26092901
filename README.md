# acltree

纯内存、单线程的文件树 ACL 继承与最小权限违规增量维护库。

## 模型

- `AddFile` 自动创建缺失的中间目录；目录与文件都可设显式 ACL，
  条目为（组，read/write，allow/deny），每个节点另有 `inherit` 标志（默认真）。
- 有效权限：从文件自身向上找最近一个对该（组，权限）有显式条目的节点，
  同节点 deny 优先；查找到 `inherit` 为假的节点为止（含）。找不到即无权限。
- 策略为（id，组，根目录，允许的权限集合），根目录可尚不存在；
  对文件 f 和组 g 适用根目录离 f 最近的策略。实际拥有而策略不允许即违规。

## 接口

```go
tr := acltree.New()
tr.AddFile("/a/b/f")
tr.SetACL("/a", []acltree.ACLEntry{{Group: "g", Perm: acltree.Write, Effect: acltree.Allow}}, true)
tr.ApplyPolicies([]acltree.Policy{{ID: "p1", Group: "g", Root: "/a",
    Allowed: map[acltree.Perm]bool{acltree.Read: true}}}, nil)
tr.Move("/a/b", "/a/c")   // 文件身份跨移动不变
tr.Remove("/a/c")         // 删除整棵子树
open := tr.Violations(false) // 持续存在的违规跨调用始终是同一条记录
```

## 性质

- 每次变更操作分配递增序号；违规记录带 `Opened`/`Resolved` 序号。
- 任意操作结束后，未解决违规集合与从零全量计算完全一致（差分测试验证）。
- 增量维护：`SetACL`/`Remove` 只触及该子树，`Move` 只触及被移动子树，
  `ApplyPolicies` 只触及所涉根目录下的子树，且整批原子生效。
- 非法输入（同组同根策略、批超 500 条、Move 到自身子树、目标不存在或重名）
  整体拒绝且状态不变。

## 测试

```sh
go test ./...
```

包含：固定种子数千步随机操作的差分测试（对照独立朴素全量计算器，
并校验记录身份与序号）、策略替换/批原子性/非法输入的定向用例、规模 sanity。
