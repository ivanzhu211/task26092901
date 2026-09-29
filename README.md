# task26092901

`acltree`：纯内存、单线程的 Go 库，维护文件树上的 ACL 继承，并随每次变更
增量维护违反最小权限策略的违规记录。

## 模型

- `AddFile` 自动创建缺失的中间目录；目录和文件都可通过 `SetACL` 设置显式
  ACL（条目为 组 × read/write × allow/deny），每个节点另有 `inherit` 标志
  （默认为真）。
- 有效权限：从文件自身向上找最近一个对（组，权限）有显式条目的节点，同一
  节点 deny 优先；查找到 `inherit=false` 的节点为止（含该节点）。
- 策略为（id，组，根目录，允许的权限集合），根目录可以尚不存在。对文件 f
  和组 g，适用 g 的策略中根目录离 f 最近的一条；实际拥有而策略不允许即构成
  一条违规。

## 操作

`AddFile` / `Remove` / `Move` / `SetACL` / `ApplyPolicies`（一批最多 500 条，
整批原子生效）/ `Violations(includeResolved)`。每次变更分配递增序号；违规
记录以（文件，策略 id，组，权限）为身份，带 `Opened` / `Resolved` 序号。

## 复杂度

变更只重算受影响子树：`SetACL`/`Remove` 与节点子树规模成正比，`Move` 与被
移动子树成正比，`ApplyPolicies` 与所涉根目录下的子树成正比。

## 测试

- `engine_test.go`：定向用例（嵌套策略接管、批原子性、deny 优先、
  inherit 截断、非法输入拒绝、Move 保持记录同一性）。
- `diff_test.go`：固定种子数千步随机操作，每步与独立朴素全量计算器比对未
  解决违规，并校验持续存在的违规仍是同一条记录。

运行：`go test ./...`
