

```rust
      ctx.sys
                .call_with_flags::<&str, (), ()>("Reload", MethodFlags::AllowInteractiveAuth.into(), &())
                .await?;
```