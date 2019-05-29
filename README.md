## alita-login

alita-login is login management extension for Alita。

## Installing
```
pip install alita-login
```

## Quick Start
```
from alita import Alita
from alita_login import LoginManager

app = Alita('dw')
login_manager = LoginManager(login_view='login')
login_manager.init_app(app)

```

## Links

- Code: https://github.com/dwpy/alita-login