<p aling="center"><a href="https://github.com/distillium/motd">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="./media/logo.png" />
   <source media="(prefers-color-scheme: light)" srcset="./media/logo-black.png" />
   <img alt="distillium/motd" src="https://github.com/distillium/motd" />
 </picture>
</a></p>

![screenshot](./media/preview.png)

> [!CAUTION]  
> **THIS SCRIPT COMPLETELY REPLACES THE STANDARD MOTD AND INSTALLS A CUSTOM ONE. IT WILL NOT BE POSSIBLE TO DELETE, REVERT TO THE STANDARD MOTD OR INSTALL ANOTHER CUSTOM MOTD AFTER INSTALLATION**

> [!IMPORTANT]  
> **BY PROCEEDING WITH THE INSTALLATION, YOU ACKNOWLEDGE THAT YOU HAVE READ THE ABOVE WARNING AND AGREE TO THE PROPOSED INSTALLATION METHOD**

## Installation (root):

```
bash <(curl -fsSL https://raw.githubusercontent.com/distillium/motd/main/install-motd.sh)
```

## Commands

- `rw-motd` — manually display the current MOTD.

- `rw-motd-set` — open a menu to enable/disable MOTD info blocks and logo
