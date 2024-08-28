parser的工作是將傳入的字串，做解碼，如果沒有錯誤，則可以轉換成jwt.Token

接下來我們會對此jwt.Token開始驗證(可以參考`Parser.validate`)

1. keyFunc != nil 確保有途徑取得鑰匙: 由於最後需要對整個加密出來的鑰匙做驗證，而驗證需要使用到key，所以必須提供此途徑
2. validateHeader 驗證header: 通常header會提供alg, typ, 程式會幫你確定typ的部分為`JWT`, 至於alg程式就不多做驗證，需要由您自己決定**您的server有提供那些演算法**名稱`
3. p.validator.Validate(token.Claims) 驗證標準格式的claims: 這部分在一開始的Parser建立時，就要指定有要驗證那些標準claims，接著程式會依據設定自動執行
4. keys, _ := keyFunc(token) 取得鑰匙: 若為非對稱式加密，則提供公鑰，此鑰匙用於對加密的內容進行驗證，能證明內容都是來自於某一個私鑰加密而來
5. token.SigningMethod.Verify(signingBytes, signature, key): 取得鑰匙後就能對整個內容進行認證
6. 全部都完成之後，如果你還有自定義的claims還可以再做驗證
