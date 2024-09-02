# JWT

本專案主要參考[golang-jwt](https://github.com/golang-jwt/jwt)所製作，目的是為了更了解JWT

## Usage

請參考:

- [token_test.go](token_test.go)
- [parser_test.go](parser/parser_test.go)

## 學習

- 演算法: 要做JWT之前應該對一些加密、驗證的算法有一些了解，因此建議可以參考[crypto_test.go](test/crypto_test.go)
- 實作: 在演算法了解之後，可以嘗試用某幾種演算法去實作，HMAC是最簡單去做的，因為它是對稱式加密，沒有公鑰和私鑰，可以參考此次的[提交](https://github.com/CarsonSlovoka/jwt/commit/fd8963dc627dd9c7c9e033292affebba799bd48f)
- [ISigningMethod](https://github.com/CarsonSlovoka/jwt/blob/576547944afc94792993fd18b1addc85daff5a40/signing_method.go#L3-L15): 在實做了幾種演算法之後，就可以找到相關的規律，可以將這些內容包裝在interface之中, [commit](https://github.com/CarsonSlovoka/jwt/commit/d59b5602a018188985e96188957e7dbd1bec3af6)

> 有些演算法比較特別(例如:ecdsa)，為了要迎合接口的定義，需要[特別安排](https://github.com/CarsonSlovoka/jwt/blob/576547944afc94792993fd18b1addc85daff5a40/ecdsa.go#L72-L84)加簽出來的內容

## 與golang-jwt的差異

**自定義驗證**

它在Parse之後就能使用token.Valid來判斷該jwt字串是否合法

本專案對此需要進一步的判斷才能得知，可以傳入自定義的Header驗證邏輯，或者Validate驗證函數

此內容請參考[parser.validate](https://github.com/CarsonSlovoka/jwt/blob/576547944afc94792993fd18b1addc85daff5a40/parser/parser.go#L108-L113)

---

**不預先註冊簽章方法**

golang-jwt預設有幫忙註冊好演算法的方法名稱，因此其實他們並沒有特別提供header的驗證，會自動做好

本專案對此不提供預先的註冊，純粹讓使用者自己定義，因為並非所有伺服器都有支持很多種的加簽演算法

另外當您自己提供之後，也能對整個過程更清楚，而不會被語法糖所寵壞。
