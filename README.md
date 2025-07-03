# pomoc
## Business Logic

### ✅ **Primjer: `add_customer` funkcija sa validacijom**

```php
/**
 * Dodaje novog customer-a u bazu
 * Ovdje se radi validacija unutar Service sloja prije slanja DAO-u
 */
public function add_customer($customer) {

    // ✅ Provjera: first_name obavezno
    if (empty($customer['first_name'])) {
        Flight::halt(400, "First name is required!");
    }

    // ✅ Provjera: last_name obavezno
    if (empty($customer['last_name'])) {
        Flight::halt(400, "Last name is required!");
    }

    // ✅ Provjera: birth_date obavezno
    if (empty($customer['birth_date'])) {
        Flight::halt(400, "Birth date is required!");
    }

    // ✅ Provjera: status mora biti validna vrijednost
    if (!in_array($customer['status'], ['active', 'inactive'])) {
        Flight::halt(400, "Invalid status value! Allowed: active or inactive.");
    }

    // Ako sve prođe, zove DAO da upiše podatke u bazu
    return $this->dao->add_customer($customer);
}




✅ Primjer: update_customer funkcija sa validacijom

/**
 * Ažurira customer-a u bazi
 * Prvo provjeri da ID ima smisla i da polja nisu prazna
 */
public function update_customer($id, $customer) {

    // ✅ Provjera: ID mora biti veći od 0
    if ($id <= 0) {
        Flight::halt(400, "Invalid customer ID!");
    }

    // ✅ Provjera: first_name ne smije biti prazno
    if (empty($customer['first_name'])) {
        Flight::halt(400, "First name is required!");
    }

    // ✅ Provjera: last_name ne smije biti prazno
    if (empty($customer['last_name'])) {
        Flight::halt(400, "Last name is required!");
    }

    // ✅ Provjera: birth_date ne smije biti prazno
    if (empty($customer['birth_date'])) {
        Flight::halt(400, "Birth date is required!");
    }

    // ✅ Provjera: status je ili active ili inactive
    if (!in_array($customer['status'], ['active', 'inactive'])) {
        Flight::halt(400, "Invalid status value!");
    }

    // Ako je sve ok ➜ šalje DAO-u da napravi UPDATE
    return $this->dao->update_customer($id, $customer);
}




✅ Primjer: delete_customer funkcija sa minimalnom validacijom

/**
 * Briše customer-a
 * Ovdje samo validiraš ID
 */
public function delete_customer($customer_id) {

    // ✅ Provjera: ID mora biti pozitivan broj
    if ($customer_id <= 0) {
        Flight::halt(400, "Invalid customer ID!");
    }

    return $this->dao->delete_customer($customer_id);
}

# ✅ CRUD Service Functions — Full Validations

---

## ✅ ADD funkcija sa validacijama

```php
/**
 * Dodaje novi proizvod (ili customer) u bazu
 * Validacija: obavezna polja, cijena, status, SKU jedinstven
 */
public function add_product($product) {

    // Provjeri obavezna polja
    if (empty($product['name'])) {
        Flight::halt(400, "Product name is required!");
    }

    if (empty($product['price'])) {
        Flight::halt(400, "Price is required!");
    }

    // Provjeri da cijena nije negativna
    if ($product['price'] <= 0) {
        Flight::halt(400, "Price must be greater than zero!");
    }

    // Provjeri status
    if (!in_array($product['status'], ['active', 'inactive'])) {
        Flight::halt(400, "Invalid status! Must be 'active' or 'inactive'.");
    }

    // Provjeri da SKU ne postoji
    $sku_exists = $this->dao->get_product_by_sku($product['sku']);
    if ($sku_exists) {
        Flight::halt(400, "SKU already exists!");
    }

    // Provjeri dužinu naziva
    if (strlen($product['name']) < 3) {
        Flight::halt(400, "Product name must be at least 3 characters long!");
    }

    // Ako sve OK ➜ poziva DAO da upiše podatke
    return $this->dao->add_product($product);
}
```

---

## ✅ UPDATE funkcija sa validacijama

```php
/**
 * Ažurira proizvod po ID-u
 * Validacija: ID, obavezna polja, cijena, status
 */
public function update_product($id, $product) {

    // Provjeri ID
    if ($id <= 0) {
        Flight::halt(400, "Invalid product ID!");
    }

    if (empty($product['name'])) {
        Flight::halt(400, "Product name is required!");
    }

    if (empty($product['price'])) {
        Flight::halt(400, "Price is required!");
    }

    if ($product['price'] <= 0) {
        Flight::halt(400, "Price must be positive!");
    }

    if (!in_array($product['status'], ['active', 'inactive'])) {
        Flight::halt(400, "Invalid status!");
    }

    return $this->dao->update_product($id, $product);
}
```

---

## ✅ DELETE funkcija sa validacijom

```php
/**
 * Briše proizvod po ID-u
 * Validacija: ID > 0
 */
public function delete_product($id) {
    if ($id <= 0) {
        Flight::halt(400, "Invalid product ID!");
    }
    return $this->dao->delete_product($id);
}
```

---

## ✅ Primjeri dodatnih validacija

```php
// Broj mora biti pozitivan
if ($data['quantity'] < 0) {
  Flight::halt(400, "Quantity cannot be negative!");
}

// Status mora biti 'active' ili 'inactive'
if (!in_array($data['status'], ['active', 'inactive'])) {
  Flight::halt(400, "Invalid status value!");
}

// Provjeri email format
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
  Flight::halt(400, "Invalid email format!");
}

// Provjeri datum
if (!strtotime($data['delivery_date'])) {
  Flight::halt(400, "Invalid date format!");
}

// Provjeri duplikat (npr. email, SKU, barcode)
$exists = $this->dao->get_product_by_sku($data['sku']);
if ($exists) {
  Flight::halt(400, "SKU already exists!");
}
```

---

## ✅ Šalabahter pravila

```
- always check empty() za obavezna polja
- always check broj > 0 (price, quantity)
- in_array() za status, role, category
- filter_var() za email format
- strtotime() za datume
- rowCount() za UPDATE i DELETE ➜ znaš je li nešto pogođeno
- lastInsertId() za INSERT ➜ vrati novi ID
- Flight::halt(400, "Poruka") ➜ kad nešto nije validno
```

---

## ✅ Kako objašnjavaš na ispitu

- Service sloj ➜ *validira sve podatke prije slanja DAO sloju*.
- Ako validacija ne prođe ➜ *Flight::halt* odmah prekida i vraća status *400 Bad Request*.
- DAO sloj ➜ *prima samo ispravan, validan input*.





## Šabloni validacija u Service sloju

- Obavezna polja: empty($data['field'])
- Dozvoljene vrijednosti: in_array($value, ['opcija1', 'opcija2'])
- ID mora biti pozitivan: if ($id <= 0)
- Ako nešto nije validno ➜ Flight::halt(400, "Poruka")
- Ako je sve validno ➜ šalješ DAO-u da radi SQL
## 🧩 Validacije za bilo koju bazu (customers, products, orders, menu)

✅ Obavezna polja ➜ empty($data['field'])
✅ Brojevi ➜ > 0
✅ Status ➜ in_array(['active','inactive'])
✅ Kategorija ➜ in_array(['food','drink','dessert'])
✅ Email ➜ filter_var($data['email'], FILTER_VALIDATE_EMAIL)
✅ Datum ➜ strtotime($data['delivery_date'])
✅ Unikat ➜ get_by_sku($data['sku']) ➜ if ($sku_exists)
✅ Dužina stringa ➜ strlen($data['name'])
✅ ID ➜ $id > 0












# MIDDLEWARE

# ✅ JWT & Middleware — Šalabahter za ispit

---

## ✅ Šta je Middleware?

- Middleware je sloj koji stoji **između requesta i response-a**.
- Služi za **autentifikaciju**, autorizaciju, logging, kompresiju, i druge “cross-cutting” stvari.
- U **FlightPHP** ➜ Middleware možeš dodati na **pojedinačne rute**, grupu ruta, ili globalno (`/*`).

---

## ✅ JWT logika (kako radi)

✔️ **Autentikacija** ➜ Provjera ko si (login ➜ dobiješ token)  
✔️ **Autorizacija** ➜ Provjera šta smiješ (role/permissions u payload-u)

- JWT se kreira kad user prođe login:
```php
$jwt_payload = [
  'user' => $user,
  'iat' => time(),
  'exp' => time() + (60 * 60 * 24)
];
$token = JWT::encode($jwt_payload, Config::JWT_SECRET(), 'HS256');
```

- Klijent šalje token u **Authorization header**:
```
Authentication: Bearer {token}
```

- Backend `decode`-uje token:
```php
$decoded_token = JWT::decode($token, new Key(Config::JWT_SECRET(), 'HS256'));
Flight::set('user', $decoded_token->user);
```

---

## ✅ Glavne Middleware funkcije (primjeri)

```php
class AuthMiddleware {

  // Provjeri da li postoji token i dekodiraj ga
  public function verifyToken($token) {
    if(!$token)
      Flight::halt(401, "Missing authentication header");

    $decoded_token = JWT::decode($token, new Key(Config::JWT_SECRET(), 'HS256'));

    Flight::set('user', $decoded_token->user);
    Flight::set('jwt_token', $token);
    return TRUE;
  }

  // Provjeri da li user ima tačno određenu rolu
  public function authorizeRole($requiredRole) {
    $user = Flight::get('user');
    if ($user->role !== $requiredRole) {
      Flight::halt(403, 'Access denied: insufficient privileges');
    }
  }

  // Provjeri da li user ima jednu od dozvoljenih rola
  public function authorizeRoles($roles) {
    $user = Flight::get('user');
    if (!in_array($user->role, $roles)) {
      Flight::halt(403, 'Forbidden: role not allowed');
    }
  }

  // Provjeri da li user ima određenu permisiju
  public function authorizePermission($permission) {
    $user = Flight::get('user');
    if (!in_array($permission, $user->permissions)) {
      Flight::halt(403, 'Access denied: permission missing');
    }
  }
}
```

---

## ✅ Kako Middleware koristiš u index.php

```php
// Ova ruta se izvršava za sve zahtjeve
Flight::route('/*', function() {
  if(
    strpos(Flight::request()->url, '/auth/login') === 0 ||
    strpos(Flight::request()->url, '/auth/register') === 0
  ) {
    return TRUE; // Ove rute su javne
  } else {
    try {
      $token = Flight::request()->getHeader("Authentication");
      Flight::auth_middleware()->verifyToken($token);
      return TRUE;
    } catch (\Exception $e) {
      Flight::halt(401, $e->getMessage());
    }
  }
});
```

---

## ✅ Kratke napomene za ispit

- ✔️ Ako `verifyToken` baci grešku ➜ 401 Unauthorized.
- ✔️ Ako `authorizeRole` ne prođe ➜ 403 Forbidden.
- ✔️ `Flight::set('user', ...)` ➜ user payload je globalno dostupan.
- ✔️ Ako middleware vrati `false` ➜ Flight odmah prekida izvršenje rute.

---

## ✅ Kako da iskoristiš u ruti

```php
$middleware = new AuthMiddleware();
$token = Flight::request()->getHeader("Authentication");
$middleware->verifyToken($token);

// Ako ruta smije samo admin
$middleware->authorizeRole('admin');

// Ako smije više rola
$middleware->authorizeRoles(['admin', 'manager']);

// Ako smije samo s permisijom
$middleware->authorizePermission('edit-products');

// Ostatak rute...
$service = new ExamService();
Flight::json($service->get_customers());
```

---

## ✅ Najvažnije rečenice koje zapamtiš

✔️ **Middleware ➜ filtrira request prije nego dođe do rute.**  
✔️ **JWT ➜ potvrđuje identitet, payload sadrži role i permissions.**  
✔️ **Flight::halt ➜ odmah prekida s error porukom i statusom.**  
✔️ **`/*` wildcard ➜ globalna zaštita, osim za login/register.**

---

**✅ To je tvoj Middleware šalabahter! Spremi ga u README i samo ga koristi!**


## 🟢 ✅ MIDDLEWARE SKELET
Zapiši ovo u README ili drži kao AuthMiddleware.php

```php
<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthMiddleware {

  /**
   * ✅ Token verifikacija
   * Provjerava da li je token prisutan i validan.
   */
  public function verifyToken($token) {
    if (!$token) {
      Flight::halt(401, "Missing authentication header");
    }

    $decoded_token = JWT::decode($token, new Key(Config::JWT_SECRET(), 'HS256'));

    // Sačuvaj user payload globalno
    Flight::set('user', $decoded_token->user);
    Flight::set('jwt_token', $token);
    return TRUE;
  }

  /**
   * ✅ Autorizacija jedne role
   * Dozvoljava pristup samo ako user ima tačnu rolu.
   */
  public function authorizeRole($requiredRole) {
    $user = Flight::get('user');
    if ($user->role !== $requiredRole) {
      Flight::halt(403, 'Access denied: insufficient privileges');
    }
  }

  /**
   * ✅ Autorizacija više rola
   * Dozvoljava pristup ako user ima BILO KOJU od navedenih rola.
   */
  public function authorizeRoles($roles) {
    $user = Flight::get('user');
    if (!in_array($user->role, $roles)) {
      Flight::halt(403, 'Forbidden: role not allowed');
    }
  }

  /**
   * ✅ Autorizacija permisija
   * Dozvoljava pristup samo ako user ima određenu permisiju.
   */
  public function authorizePermission($permission) {
    $user = Flight::get('user');
    if (!in_array($permission, $user->permissions)) {
      Flight::halt(403, 'Access denied: permission missing');
    }
  }

  /**
   * ✅ (Opcija) Logging, rate limiter ili audit
   * Ovdje možeš ubaciti logiku za logovanje ili brojanje requesta.
   */
  public function logRequest($routeName) {
    // Primjer: Loguj ime rute i user ID
    $user = Flight::get('user');
    error_log("User {$user->id} pristupa ruti: {$routeName}");
  }
}
?>










# MYSQL QUERIJI I TODO

✅ 2) GET /customers
Šta traži: Vraća sve customers (za <select> listu).

DAO upit:

SELECT * FROM customers


U PHP-u

public function get_customers() {
    $stmt = $this->conn->query("SELECT * FROM customers");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}




✅ 3) GET /customer/meals/@customer_id
Šta traži:
- Vraća sve obroke za određenog customer-a.
- Svaki item ima: food_name, food_brand, meal_date.
- Znači ➜ JOIN tabele meals i foods.

DAO upit:

SELECT 
  f.name AS food_name,
  f.brand AS food_brand,
  m.date AS meal_date
FROM meals m
JOIN foods f ON m.food_id = f.id
WHERE m.customer_id = ?


u php:

public function get_customer_meals($customer_id) {
    $stmt = $this->conn->prepare("
        SELECT f.name AS food_name, f.brand AS food_brand, m.date AS meal_date
        FROM meals m
        JOIN foods f ON m.food_id = f.id
        WHERE m.customer_id = ?
    ");
    $stmt->execute([$customer_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}



✅ 4) POST /customers/add
Šta traži:
- Dodaje novog customer-a.
- Polja: first_name, last_name, birth_date.

DAO upit:

INSERT INTO customers (first_name, last_name, birth_date)
VALUES (?, ?, ?)

u php:

public function add_customer($data) {
    $stmt = $this->conn->prepare("
        INSERT INTO customers (first_name, last_name, birth_date)
        VALUES (?, ?, ?)
    ");
    $stmt->execute([
        $data['first_name'],
        $data['last_name'],
        $data['birth_date']
    ]);
    return $this->conn->lastInsertId();
}


✅ 5) GET /foods/report
Šta traži:
- Vraća sve foods sa GROUP BY i SUM nutrijenata.
- Svaki item: name, brand, image, energy, protein, fat, fiber, carbs.
- Još ➜ paginacija (LIMIT i OFFSET).

DAO upit:

SELECT 
  f.name,
  f.brand,
  f.image,
  SUM(fn.energy) AS energy,
  SUM(fn.protein) AS protein,
  SUM(fn.fat) AS fat,
  SUM(fn.fiber) AS fiber,
  SUM(fn.carbs) AS carbs
FROM foods f
JOIN food_nutrients fn ON f.id = fn.food_id
GROUP BY f.id
LIMIT ?, ?



u php:

public function get_foods_report($offset, $limit) {
    $stmt = $this->conn->prepare("
        SELECT 
          f.name,
          f.brand,
          f.image,
          SUM(fn.energy) AS energy,
          SUM(fn.protein) AS protein,
          SUM(fn.fat) AS fat,
          SUM(fn.fiber) AS fiber,
          SUM(fn.carbs) AS carbs
        FROM foods f
        JOIN food_nutrients fn ON f.id = fn.food_id
        GROUP BY f.id
        LIMIT ?, ?
    ");
    $stmt->bindParam(1, $offset, PDO::PARAM_INT);
    $stmt->bindParam(2, $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}





✅ 6) PUT /customers/update/@id
Šta traži:

- Ažurira customer-a po ID-u.

DAO upit:

UPDATE customers 
SET first_name = ?, last_name = ?, birth_date = ?
WHERE id = ?


u php:

public function update_customer($id, $data) {
    $stmt = $this->conn->prepare("
        UPDATE customers 
        SET first_name = ?, last_name = ?, birth_date = ?
        WHERE id = ?
    ");
    $stmt->execute([
        $data['first_name'],
        $data['last_name'],
        $data['birth_date'],
        $id
    ]);
    return $stmt->rowCount();
}


✅ 7) DELETE /customers/delete/@id
Šta traži:

Briše customer-a po ID-u.

dao upit:

DELETE FROM customers WHERE id = ?


u php:

public function delete_customer($id) {
    $stmt = $this->conn->prepare("DELETE FROM customers WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->rowCount();
}








# TESTIRANJE RUTA

✅ 1) Šta ide u URL
Tvoja struktura je:

bash
Copy
Edit
http://localhost/[IME PROJEKTA]/backend/rest/[RUTA]
📌 Znači:

localhost ➜ jer radiš lokalno.

final-2025-fall ➜ ime tvog foldera na Desktopu (ili gdje god je).

backend/rest ➜ putanja gdje su ti ExamRoutes i ExamService.

/customers, /customer/meals/1, /customers/add ➜ ruta iz Flight-a.



✅ Primjeri URL-ova za Postman

| Šta testiraš                 | URL primjer                                                        |
| ---------------------------- | ------------------------------------------------------------------ |
| `GET /customers`             | `http://localhost/final-2025-fall/backend/rest/customers`          |
| `GET /customer/meals/1`      | `http://localhost/final-2025-fall/backend/rest/customer/meals/1`   |
| `POST /customers/add`        | `http://localhost/final-2025-fall/backend/rest/customers/add`      |
| `PUT /customers/update/1`    | `http://localhost/final-2025-fall/backend/rest/customers/update/1` |
| `DELETE /customers/delete/1` | `http://localhost/final-2025-fall/backend/rest/customers/delete/1` |
| `GET /foods/report`          | `http://localhost/final-2025-fall/backend/rest/foods/report`       |




✅ 2) Kako to testiraš u Postman-u
🔵 GET request
Odaberi GET.

U URL stavi npr.:

http://localhost/final-2025-fall/backend/rest/customers

Klikni Send.



🔵 POST request
Odaberi POST.

URL npr.:

http://localhost/final-2025-fall/backend/rest/customers/add

Idi na Body ➜ raw ➜ JSON.

Upisi:

{
  "first_name": "John",
  "last_name": "Doe",
  "birth_date": "1990-05-05",
  "status": "active"
}

Klikni Send.



🔵 PUT request
Odaberi PUT.

URL:

http://localhost/final-2025-fall/backend/rest/customers/update/1


Body ➜ raw ➜ JSON:

{
  "first_name": "Updated",
  "last_name": "Name",
  "birth_date": "1991-01-01",
  "status": "inactive"
}


Klikni Send.



🔵 DELETE request
Odaberi DELETE.

URL:

http://localhost/final-2025-fall/backend/rest/customers/delete/1


Klikni Send.


🗝️ Brzi šalabahter za port
Ako koristiš PHP built-in server:

php -S localhost:8000
➜ URL je: http://localhost:8000/final-2025-fall/backend/rest/...

Ako koristiš XAMPP/WAMP ➜ port je obično 80, pa pišeš samo localhost bez :80.









# FRONTEND

✅ Šalabahter: Dinamički SELECT

// 1. Dinamički SELECT
function loadCustomers() {
  fetch("/customers")
    .then(res => res.json())
    .then(data => {
      selectEl.innerHTML = '<option selected>Please select one customer</option>';
      data.forEach(customer => {
        const option = document.createElement("option");
        option.value = customer.id; // ili customer.customer_id, zavisi od response
        option.textContent = customer.name || (customer.first_name + ' ' + customer.last_name);
        selectEl.appendChild(option);
      });
    });
}

✔️ Kad to koristiš?
Kad u HTML-u imaš <select> i trebaš da ga puniš podacima iz baze (npr. customers, categories, products).




✅ Šalabahter: OnChange event za <select>


// 2. Na promjenu SELECT-a, load-aj povezane podatke
selectEl.addEventListener("change", function() {
  const customerId = this.value;
  if (!customerId) return;

  fetch(`/customer/meals/${customerId}`)
    .then(res => res.json())
    .then(data => {
      tableBody.innerHTML = "";
      data.forEach(meal => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${meal.food_name}</td>
          <td>${meal.food_brand}</td>
          <td>${meal.meal_date}</td>
        `;
        tableBody.appendChild(tr);
      });
    });
});


✔️ Kad to koristiš?
Kad hoćeš da odabir u <select> filtrira šta se prikazuje u tabeli ili listi.






✅ Šalabahter: POST forma


// 3. Submit forme ➜ POST
form.addEventListener("submit", function(e) {
  e.preventDefault();

  const payload = {
    first_name: document.getElementById("first_name").value,
    last_name: document.getElementById("last_name").value,
    birth_date: document.getElementById("birth_date").value
  };

  fetch("/customers/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
    .then(res => res.json())
    .then(newCustomer => {
      loadCustomers(); // refreshuje SELECT
      const modal = bootstrap.Modal.getInstance(document.getElementById("add-customer-modal"));
      modal.hide();
      form.reset();
    });
});


✔️ Kad to koristiš?
Kad imaš modal/formu za dodavanje podataka i želiš AJAX POST.




✅ Šalabahter: GET za prikaz tabele (foods.html)
Ako profesorica traži da foods.html puni tabelu iz baze, to bi bio jednostavan fetch:


function loadFoods(offset = 0, limit = 10) {
  fetch(`/foods/report?offset=${offset}&limit=${limit}`)
    .then(res => res.json())
    .then(data => {
      const tbody = document.querySelector("table tbody");
      tbody.innerHTML = "";
      data.forEach(food => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${food.name}</td>
          <td>${food.brand}</td>
          <td class="text-center"><img src="${food.image}" height="50" /></td>
          <td>${food.energy}</td>
          <td>${food.protein}</td>
          <td>${food.fat}</td>
          <td>${food.fiber}</td>
          <td>${food.carbs}</td>
        `;
        tbody.appendChild(tr);
      });
    });
}

document.addEventListener("DOMContentLoaded", loadFoods);






1️⃣ Populate <select> element with all customers

Šta trebaš uraditi:
Trebaš napuniti <select> listu sa svim korisnicima iz baze.

Znači, trebaš napraviti GET request za rutu /customers, uzeti sve korisnike iz baze, i dynamically popuniti <select> listu sa tim podacima.

Kako to implementirati:
HTML za <select> (već imaš u svom HTML-u):


<select class="form-select" id="customers-list">
  <option selected>Please select one customer</option>
</select>


JS funkcija koja puni <select>:


function loadCustomers() {
  fetch("/customers")  // Pošaljemo GET zahtjev na /customers
    .then(res => res.json())  // Pretvaramo odgovor u JSON
    .then(data => {
      const selectEl = document.getElementById("customers-list");
      selectEl.innerHTML = '<option selected>Please select one customer</option>';
      data.forEach(customer => {
        const option = document.createElement("option");
        option.value = customer.id;  // Puni ID korisnika
        option.textContent = customer.first_name + " " + customer.last_name;  // Ime i prezime korisnika
        selectEl.appendChild(option);
      });
    });
}

document.addEventListener("DOMContentLoaded", loadCustomers);  // Kada se stranica učita, pozivamo funkciju



Objašnjenje šta se dešava:
fetch("/customers"): Ovdje šaljemo GET request na backend da uzmemo sve korisnike.

.then(res => res.json()): Čekamo odgovor od servera i konvertujemo ga u JSON.

data.forEach(customer => { ... }): Iteriramo kroz sve korisnike koje smo dobili i dinamički dodajemo <option> u <select>.

selectEl.appendChild(option): Dodajemo svaku opciju u HTML <select> listu.

Šta se mijenja za ispit:
Ako profesorica traži nešto drugo za popunjavanje (npr. products umjesto customers) samo zamijeni /customers u /products i imena polja u kodu (ako se razlikuju).





2️⃣ Fetch meals for selected customer and populate the table
Šta trebaš uraditi:
Kad korisnik odabere novog korisnika u <select>, trebaš uzeti njegove obroke iz baze i napuniti tabelu sa podacima o obrocima.

Kako to implementirati:
HTML za tabelu (već postoji):


<table class="table table-striped" id="customer-meals">
  <thead>
    <tr>
      <th>Food name</th>
      <th>Food brand</th>
      <th>Meal date</th>
    </tr>
  </thead>
  <tbody>
    <!-- Tabela će biti dinamički popunjena -->
  </tbody>
</table>



JS funkcija koja se poziva kad se odabere korisnik:


const selectEl = document.getElementById("customers-list");
const tableBody = document.querySelector("#customer-meals tbody");

selectEl.addEventListener("change", function () {
  const customerId = this.value;
  if (!customerId || customerId === "Please select one customer") return;

  fetch(`/customer/meals/${customerId}`)  // Pošaljemo GET zahtjev za obrocima korisnika
    .then(res => res.json())  // Pretvaramo odgovor u JSON
    .then(meals => {
      tableBody.innerHTML = "";  // Očistimo postojeću tabelu
      meals.forEach(meal => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${meal.food_name}</td>
          <td>${meal.food_brand}</td>
          <td>${meal.meal_date}</td>
        `;
        tableBody.appendChild(tr);  // Dodajemo svaki red u tabelu
      });
    });
});





Objašnjenje šta se dešava:
selectEl.addEventListener("change", function() {...}): Kada korisnik odabere drugog korisnika, ovo pokreće funkciju.

fetch(/customer/meals/${customerId}): Šaljemo GET request na rutu /customer/meals/{id} da uzmemo obroke za odabranog korisnika.

meals.forEach(meal => { ... }): Iteriramo kroz sve obroke i za svaki unos u tabelu pravimo novi <tr> (red tabele).

Šta se mijenja za ispit:
Ako profesorica pita da radimo za foods umjesto meals, samo promijeniš URL u fetch("/food/items/${foodId}") i odgovarajući kod za unos podataka u tabelu.





3️⃣ Add new customer using modal

Šta trebaš uraditi:
Trebaš implementirati modal za dodavanje novog korisnika u bazu.

Kada korisnik klikne na dugme "Save changes", podaci iz forme treba da se pošalju backendu pomoću POST.



Kako to implementirati:
HTML za modal (već postoji):


<div class="modal fade" id="add-customer-modal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="add-customer-form">
        <div class="modal-header">
          <h5 class="modal-title">Add Customer</h5>
        </div>
        <div class="modal-body">
          <input type="text" id="first_name" placeholder="First name" />
          <input type="text" id="last_name" placeholder="Last name" />
          <input type="date" id="birth_date" />
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Save changes</button>
        </div>
      </form>
    </div>
  </div>
</div>


JS za submit forme:

const form = document.getElementById("add-customer-form");

form.addEventListener("submit", function (e) {
  e.preventDefault();

  const first_name = document.getElementById("first_name").value;
  const last_name = document.getElementById("last_name").value;
  const birth_date = document.getElementById("birth_date").value;

  const payload = { first_name, last_name, birth_date };

  fetch("/customers/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
    .then(res => res.json())
    .then(() => {
      loadCustomers();  // Osvježi SELECT sa novim korisnikom
      const modal = bootstrap.Modal.getInstance(document.getElementById("add-customer-modal"));
      modal.hide();  // Zatvori modal
      form.reset();  // Resetuj formu
    });
});




Objašnjenje šta se dešava:
form.addEventListener("submit", function(e) {...}): Kada korisnik klikne na "Save changes", poziva se funkcija.

fetch("/customers/add", {...}): Šaljemo POST zahtjev sa podacima iz forme u backend.

loadCustomers(): Osvježavamo listu korisnika tako da novi korisnik bude odmah vidljiv.

Šta se mijenja za ispit:
Ako profesorica pita da dodamo proizvod, sve isto, samo promijeniš URL u /products/add i odgovarajući sadržaj u payload-u (npr. name, price, category).






# DETALJNO OBJASNJENJE ZA IMPLEMENTOVANJE JS FUNKCIJA


1️⃣ Populate <select> with all customers

Opis:
Trebaš dynamically popuniti <select> sa svim korisnicima iz baze. Ovo je osnovno kada želiš prikazati listu korisnika, proizvoda, kategorija, itd.

Na šta trebaš paziti:
id atribut za <select>: U tvom HTML-u, <select> tag ima id="customers-list". Ovo je vrlo važno jer ćeš koristiti document.getElementById("customers-list") u JS-u da dođeš do tog elementa.

fetch metodologija: Korišćenje fetch API-ja znači da ti treba ispravan URL koji vraća sve korisnike u JSON formatu.

Kako da znaš koji podaci se vraćaju: U backendu, ruta /customers treba da vraća sve korisnike u formatu:

[
  { "id": 1, "first_name": "John", "last_name": "Doe" },
  { "id": 2, "first_name": "Jane", "last_name": "Smith" }
]




Kako implementirati:


// JS - Funkcija koja puni <select>
function loadCustomers() {
  fetch("/customers")  // Get zahtjev na /customers
    .then(res => res.json())  // Pretvori odgovor u JSON
    .then(data => {
      const selectEl = document.getElementById("customers-list");  // Pazi da je id ispravan
      selectEl.innerHTML = '<option selected>Please select one customer</option>';
      data.forEach(customer => {
        const option = document.createElement("option");  // Kreiraj novi <option> tag
        option.value = customer.id;  // Postavi vrijednost kao ID korisnika
        option.textContent = `${customer.first_name} ${customer.last_name}`;  // Puni tekst sa imenom
        selectEl.appendChild(option);  // Dodaj opciju u select
      });
    });
}

document.addEventListener("DOMContentLoaded", loadCustomers);  // Kada stranica učita, pozivamo ovu funkciju


Šta se mijenja:
id="customers-list" ➜ Ovo je bitno, jer u JS-u moraš targetirati tačno ovaj <select> koristeći document.getElementById().

Ako dobijemo proizvode ili kategorije umjesto korisnika, promijenit ćemo samo /customers na /products ili /categories, a struktura JSON-a ostaje slična





2️⃣ Fetch meals for selected customer


Opis:
Kad korisnik odabere novog korisnika iz <select>, trebaš fetch obroke za tog korisnika i popuniti <table> sa podacima.

Na šta trebaš paziti:
id atribut za <table>: Tabela ima id="customer-meals". U JS-u koristiš document.querySelector("#customer-meals tbody") da dođeš do <tbody> gdje ćeš popuniti obroke.

change event listener: Kada korisnik promijeni odabrani korisnik u <select>, pozivaš fetch za obroke i puniš tabelu.

Prilagodba za ID u URL-u: U URL-u za fetch šalješ /customer/meals/${customerId} gdje je customerId ID korisnika koji je odabran.



Kako implementirati:


const selectEl = document.getElementById("customers-list");
const tableBody = document.querySelector("#customer-meals tbody");

selectEl.addEventListener("change", function() {
  const customerId = this.value;  // Uzmi ID korisnika koji je selektovan
  if (!customerId || customerId === "Please select one customer") return;  // Ako nije selektovan, izlazi

  fetch(`/customer/meals/${customerId}`)  // Pošaljemo GET zahtjev sa customerId
    .then(res => res.json())  // Pretvaramo odgovor u JSON
    .then(meals => {
      tableBody.innerHTML = "";  // Očisti staru tabelu
      meals.forEach(meal => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${meal.food_name}</td>
          <td>${meal.food_brand}</td>
          <td>${meal.meal_date}</td>
        `;
        tableBody.appendChild(tr);  // Dodaj novi red u tabelu
      });
    });
});


Šta se mijenja:
id="customer-meals" ➜ Moraš paziti da je tačno ime tabele kako bi je mogao targetirati u JS-u.

URL /customer/meals/${customerId} mora biti ispravan i moraš proslijediti ID korisnika koji je odabran u select.







3️⃣ Add customer using modal


Opis:
Koristiš modal za dodavanje korisnika. Kada popuniš formu i klikneš "Save changes", šalješ POST zahtjev sa podacima.

Na šta trebaš paziti:
Modal ID: Modal ima id="add-customer-modal". Ovaj ID moraš koristiti da zatvoriš modal nakon što je customer uspješno dodan.

Formular: Formu moraš validirati i poslati POST zahtjev sa podacima iz inputa (ime, prezime, datum rođenja).

fetch za POST: Ako se sve odradi kako treba, trebaš osvježiti listu korisnika u <select>.


Kako implementirati:


const form = document.getElementById("add-customer-form");

form.addEventListener("submit", function (e) {
  e.preventDefault();  // Spriječava reload stranice

  const first_name = document.getElementById("first_name").value;
  const last_name = document.getElementById("last_name").value;
  const birth_date = document.getElementById("birth_date").value;

  const payload = { first_name, last_name, birth_date };

  fetch("/customers/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
    .then(res => res.json())  // Nakon POST-a dobijamo response
    .then(newCustomer => {
      loadCustomers();  // Osvježavanje liste korisnika u <select>

      // Zatvori modal
      const modal = bootstrap.Modal.getInstance(
        document.getElementById("add-customer-modal")
      );
      modal.hide();
      form.reset();  // Resetuj formu
    });
});



Šta se mijenja:
id="add-customer-modal" mora biti tačan, jer koristimo bootstrap.Modal.getInstance() za zatvaranje modala.

POST URL mora biti ispravan, obavezno proslijedi podatke u JSON-u.


Zaključak:
Sada znaš tačno kako implementirati svaki TODO u JS!
Ako ti se pojavi novi zadatak, samo se prisjeti:

Popuniti <select> ➜ fetch + appendChild.

Prikazivanje podataka u <table> ➜ fetch + innerHTML.

Dodavanje novih korisnika/proizvoda ➜ fetch POST + refresh.




# POPUNJAVANJE NECEG DRUGOG OSIM SELEKTA


🟢 1. Promjena zadatka: "Popuniti <select> za proizvode"
Zadatak:
"Popuniti <select> listu sa svim proizvodima iz baze, i kada se selektuje proizvod, prikazati sve informacije o tom proizvodu (cijena, kategorija, brand, slika)."

Kako primijeniti:
HTML za select:


<select class="form-select" id="products-list">
  <option selected>Please select a product</option>
</select>


JS funkcija za popunjavanje select:

function loadProducts() {
  fetch("/products")  // Promijenimo URL u /products
    .then(res => res.json())
    .then(data => {
      const selectEl = document.getElementById("products-list");
      selectEl.innerHTML = '<option selected>Please select a product</option>';
      data.forEach(product => {
        const option = document.createElement("option");
        option.value = product.id;
        option.textContent = product.name;
        selectEl.appendChild(option);
      });
    });
}

document.addEventListener("DOMContentLoaded", loadProducts);  // Kada stranica učita, pozivamo ovu funkciju


JS za prikaz proizvoda kad se odabere:


const selectEl = document.getElementById("products-list");

selectEl.addEventListener("change", function () {
  const productId = this.value;
  if (!productId) return;

  fetch(`/product/details/${productId}`)  // Uzmi detalje za proizvod
    .then(res => res.json())
    .then(product => {
      // Popuni tabelu sa podacima o proizvodu
      document.getElementById("product-name").textContent = product.name;
      document.getElementById("product-brand").textContent = product.brand;
      document.getElementById("product-price").textContent = product.price;
      document.getElementById("product-image").src = product.image;
    });
});


Objašnjenje:
fetch("/products") ➜ Uzima sve proizvode iz baze.

<select> se puni sa imenom proizvoda.

Kad se selektuje proizvod, fetch uzima detalje i puni HTML elemente.




🟢 2. Promjena zadatka: "Popuniti tabelu sa svim korisnicima"
Zadatak:
"Prikazati tabelu sa svim korisnicima, njihovim podacima i opcijama za editovanje i brisanje."

Kako primijeniti:
HTML za tabelu:

<table class="table table-striped" id="user-table">
  <thead>
    <tr>
      <th>Name</th>
      <th>Email</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    <!-- Tabela će biti dinamički popunjena -->
  </tbody>
</table>



JS za popunjavanje tabele:


function loadUsers() {
  fetch("/users")  // URL za sve korisnike
    .then(res => res.json())
    .then(data => {
      const tableBody = document.querySelector("#user-table tbody");
      tableBody.innerHTML = "";  // Očisti staru tabelu
      data.forEach(user => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${user.first_name} ${user.last_name}</td>
          <td>${user.email}</td>
          <td>
            <button onclick="editUser(${user.id})">Edit</button>
            <button onclick="deleteUser(${user.id})">Delete</button>
          </td>
        `;
        tableBody.appendChild(tr);  // Dodaj novi red u tabelu
      });
    });
}

document.addEventListener("DOMContentLoaded", loadUsers);  // Kada stranica učita, pozivamo ovu funkciju



Objašnjenje:
fetch("/users") ➜ Uzima sve korisnike iz baze.

Popunjava se tabela sa podacima svakog korisnika.

Dugmadi za editovanje i brisanje mogu pozivati funkcije editUser() i deleteUser() (koje mogu koristiti PUT i DELETE metode).






🟢 3. Promjena zadatka: "Dodavanje proizvoda"
Zadatak:
"Implementirati modal za dodavanje proizvoda u bazu (name, price, category). Kada proizvod bude dodan, lista proizvoda u <select> mora biti ažurirana."

Kako primijeniti:
HTML za modal:


<div class="modal fade" id="add-product-modal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="add-product-form">
        <div class="modal-header">
          <h5 class="modal-title">Add Product</h5>
        </div>
        <div class="modal-body">
          <input type="text" id="product-name" placeholder="Product Name" />
          <input type="number" id="product-price" placeholder="Price" />
          <select id="product-category">
            <option value="food">Food</option>
            <option value="drink">Drink</option>
            <option value="dessert">Dessert</option>
          </select>
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Save</button>
        </div>
      </form>
    </div>
  </div>
</div>




JS za submit forme:


const form = document.getElementById("add-product-form");

form.addEventListener("submit", function (e) {
  e.preventDefault();

  const name = document.getElementById("product-name").value;
  const price = document.getElementById("product-price").value;
  const category = document.getElementById("product-category").value;

  const payload = { name, price, category };

  fetch("/products/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
    .then(res => res.json())
    .then(() => {
      loadProducts();  // Refresh proizvoda u SELECT-u
      const modal = bootstrap.Modal.getInstance(document.getElementById("add-product-modal"));
      modal.hide();  // Zatvori modal
      form.reset();  // Resetuj formu
    });
});


Objašnjenje:
Modal za dodavanje proizvoda koristi POST za dodavanje novog proizvoda.

Nakon što proizvod bude dodan, lista u <select> se automatski ažurira pozivom loadProducts().





🟢 4. Promjena zadatka: "Prikazivanje detalja proizvoda"
Zadatak:
"Na odabir proizvoda iz <select>, prikazati detalje o tom proizvodu u tabeli (name, brand, price, description, image)."

Kako primijeniti:
HTML za tabelu:


<table id="product-details">
  <thead>
    <tr>
      <th>Name</th>
      <th>Brand</th>
      <th>Price</th>
      <th>Description</th>
      <th>Image</th>
    </tr>
  </thead>
  <tbody>
    <!-- Tabela se popunjava dinamički -->
  </tbody>
</table>



JS za prikazivanje detalja proizvoda:


selectEl.addEventListener("change", function () {
  const productId = this.value;
  if (!productId) return;

  fetch(`/product/details/${productId}`)
    .then(res => res.json())
    .then(product => {
      const tableBody = document.querySelector("#product-details tbody");
      tableBody.innerHTML = `
        <tr>
          <td>${product.name}</td>
          <td>${product.brand}</td>
          <td>${product.price}</td>
          <td>${product.description}</td>
          <td><img src="${product.image}" height="50" /></td>
        </tr>
      `;
    });
});


Objašnjenje:
fetch za /product/details/${productId} vraća detalje za selektovani proizvod i prikazuje ih u tabeli.

Prilagodba: Ako profesorica zatraži kategoriju, samo promijeniš URL i ime polja.







# POPUNJAVANJE RAZLICITIH DIJELOVA STRANICE


1️⃣ Popunjavanje <textarea> elementa


Opis:
Ako ti se zada zadatak da popuniš <textarea> (na primjer, za unos opisa proizvoda ili komentara), koristiš value da postaviš vrijednost u taj element.

HTML:

<textarea id="product-description"></textarea>

JS (popunjavanje):

document.getElementById("product-description").value = product.description;


Na šta trebaš obratiti pažnju:
value je za <textarea> i koristiš ga da postaviš tekst u textbox.

Ako profesorica zatraži da popuniš opis proizvoda, samo zamijeniš URL u fetch-u, na primjer /product/details/${productId}, a ostalo ostane isto.





2️⃣ Popunjavanje <div> elementa

Opis:
Za prikazivanje podataka u <div>, koristiš innerHTML za dodavanje HTML sadržaja, ili textContent ako želiš samo tekst.

HTML:

<div id="product-details">
  <p id="product-name"></p>
  <p id="product-brand"></p>
  <p id="product-price"></p>
  <img id="product-image" />
</div>


JS (popunjavanje):

document.getElementById("product-name").textContent = product.name;
document.getElementById("product-brand").textContent = product.brand;
document.getElementById("product-price").textContent = product.price;
document.getElementById("product-image").src = product.image;


Na šta trebaš obratiti pažnju:
Ako profesorica traži prikazivanje proizvoda u <div>, samo moraš zamijeniti URL u fetch i dodati odgovarajuće HTML elemente u div.

Koristi textContent za tekstualne podatke (ime, cijena), a src za slike.




3️⃣ Popunjavanje <ul> (neuređene liste)

Opis:
Ako trebaš prikazivati stavke u listi (npr. proizvode, korisnike, komentare), koristiš <ul> i <li> tagove.

HTML:

<ul id="product-list"></ul>


JS (popunjavanje):

function loadProducts() {
  fetch("/products")
    .then(res => res.json())
    .then(data => {
      const ul = document.getElementById("product-list");
      ul.innerHTML = "";  // Očisti listu prije popunjavanja
      data.forEach(product => {
        const li = document.createElement("li");
        li.textContent = `${product.name} - $${product.price}`;
        ul.appendChild(li);  // Dodaj stavku u listu
      });
    });
}

document.addEventListener("DOMContentLoaded", loadProducts);  // Pozovi funkciju kada stranica učita



Na šta trebaš obratiti pažnju:
<ul> je za neuređene liste, a <ol> za uređene liste.

U <li> dodaješ stavke (npr. proizvode) u listu.

Kad dođeš do zadatka koji traži prikazivanje stavki, koristiš ovo rješenje. Ako profesorica traži popis korisnika, samo zamijeniš URL i prikazuješ korisničke podatke.




4️⃣ Popunjavanje <ol> (uređene liste)


Opis:
Slično kao <ul>, ali koristiš <ol> kad želiš numerisanu listu.

HTML:

<ol id="customer-list"></ol>


JS (popunjavanje):

function loadCustomers() {
  fetch("/customers")
    .then(res => res.json())
    .then(data => {
      const ol = document.getElementById("customer-list");
      ol.innerHTML = "";  // Očisti listu prije popunjavanja
      data.forEach((customer, index) => {
        const li = document.createElement("li");
        li.textContent = `${index + 1}. ${customer.first_name} ${customer.last_name}`;
        ol.appendChild(li);
      });
    });
}

document.addEventListener("DOMContentLoaded", loadCustomers);  // Pozovi funkciju kada stranica učita


Na šta trebaš obratiti pažnju:
<ol> je numerisana lista, a <ul> je neniširana.

Ako zadatak traži numerisanje, koristiš <ol> umjesto <ul>.




5️⃣ Popunjavanje input ili textarea za formu


Opis:
Za unos podataka u formu, koristiš value atribut.

HTML:

<input type="text" id="product-name" placeholder="Enter product name" />
<input type="number" id="product-price" placeholder="Enter price" />
<textarea id="product-description" placeholder="Enter description"></textarea>


JS (popunjavanje):

document.getElementById("product-name").value = product.name;
document.getElementById("product-price").value = product.price;
document.getElementById("product-description").value = product.description;



Na šta trebaš obratiti pažnju:
<input> za jednostavne podatke (tekst, broj, datum).

<textarea> za duže unose (npr. opis proizvoda, komentari).

Kad trebaš da popuniš formu, samo koristiš value za inpute ili textarea.


Zaključak:
Sada, kada ti na ispitu da zadatak da popuniš nešto, samo:

Prepoznaj tip elementa koji trebaš popuniti:

<select> — popunjavaš sa opcijama (korisnici, proizvodi, kategorije).

<table> — popunjavaš sa redovima.

<div> — prikazuješ detalje.

<ul> / <ol> — popunjavaš listu.

<input> / <textarea> — popunjavaš formu.

Prilagodi fetch i JSON odgovor sa ispravnim endpoint-om i podacima.

Započni sa osnovnim fetch metodama koje dinamički popunjavaju ove elemente.

Ako se nešto promijeni na ispitu, samo se prisjeti šta trebaš popuniti, prilagodi URL i HTML elemente.

Ako trebaš još konkretnih primjera ili detalja, slobodno javi! 💪🚀





# FETCH

Brate, super pitanje! 👌
fetch je jedan od najosnovnijih i najkorišćenijih JavaScript API-ja za slanje HTTP zahtjeva ka backend-u (npr. REST API), i on određuje URL na kojem tražiš podatke. Ako trebaš promijeniti URL u fetch, to ćeš uraditi na vrlo jednostavan način — samo zamijeniš URL unutar fetch metode.



🟢 Kako radi fetch i što je URL?
fetch osnovni primjer:

fetch("http://localhost/final-2025-fall/backend/rest/customers")  // URL
  .then(res => res.json())  // Pretvori odgovor u JSON
  .then(data => {
    console.log(data);  // Obradi podatke
  })
  .catch(error => console.error('Error:', error));


Šta radi ovaj kod?

fetch šalje HTTP GET zahtjev na http://localhost/final-2025-fall/backend/rest/customers.

then(res => res.json()) ➜ Kad dobijemo odgovor, pretvaramo ga u JSON.

data sadrži sve podatke koje si dobio sa backend-a (npr. listu korisnika).




🟢 Kako mijenjati fetch URL?
Kada trebaš promijeniti URL?
Ako profesorica promijeni endpoint na backendu, recimo da /customers postane /users, samo zamijeni URL unutar fetch-a:


Primjer prije promjene:

fetch("http://localhost/final-2025-fall/backend/rest/customers")


Primjer nakon promjene (ako je endpoint promijenjen u /users):


fetch("http://localhost/final-2025-fall/backend/rest/users")  // Promijenjen URL







2. Ako mijenjamo URL s parametrima (dinamički)
Ako trebaš da dodaš dinamički ID ili filter u URL, to izgleda ovako:

Primjer:

const customerId = 1;  // ID korisnika kojeg tražiš
fetch(`http://localhost/final-2025-fall/backend/rest/customer/meals/${customerId}`)
  .then(res => res.json())
  .then(data => {
    console.log(data);  // Obrađuješ podatke za tog korisnika
  })
  .catch(error => console.error('Error:', error));




Zašto je ovo bitno?

URL je sada dinamičan jer koristi ${customerId} za unos vrijednosti.

fetch će tražiti obroke za korisnika sa ID-om 1.


🟢 Kada koristiš dinamički URL (npr. sa parametrom)
Ako imaš dva različita URL-a (jedan za korisnike i jedan za proizvode), moraš prilagoditi URL u fetch-u prema onome što trebaš.


Primjeri:

Za customers:

fetch("http://localhost/final-2025-fall/backend/rest/customers")



Za products:

fetch("http://localhost/final-2025-fall/backend/rest/products")



Za detalje korisnika:

fetch("http://localhost/final-2025-fall/backend/rest/customer/meals/1")  // ID = 1



Za proizvode u određenoj kategoriji:

fetch("http://localhost/final-2025-fall/backend/rest/products?category=food")





🟢 Kada je fetch potrebno za POST, PUT, ili DELETE?
Za POST, PUT, ili DELETE koristiš isti princip, samo što moraš postaviti metodu i tijelo (body).

4. POST za dodavanje novog korisnika


const payload = { first_name: "John", last_name: "Doe", birth_date: "1990-01-01" };

fetch("http://localhost/final-2025-fall/backend/rest/customers/add", {
  method: "POST",  // Post metoda
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload)  // Pretvori objekt u JSON
})
  .then(res => res.json())
  .then(newCustomer => {
    console.log(newCustomer);  // Ovdje ti dolazi novi customer
  });



5. PUT za ažuriranje korisnika

const payload = { first_name: "Updated", last_name: "Name", birth_date: "1991-01-01" };
const customerId = 1;

fetch(`http://localhost/final-2025-fall/backend/rest/customers/update/${customerId}`, {
  method: "PUT",  // Put metoda
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload)  // Pošaljemo podatke za update
})
  .then(res => res.json())
  .then(updatedCustomer => {
    console.log(updatedCustomer);  // Ovdje ti dolazi ažurirani customer
  });




6. DELETE za brisanje korisnika

const customerId = 1;

fetch(`http://localhost/final-2025-fall/backend/rest/customers/delete/${customerId}`, {
  method: "DELETE",  // Delete metoda
})
  .then(res => res.json())
  .then(response => {
    console.log(response);  // Ovdje ti dolazi odgovor o uspješnom brisanju
  });



🏆 Zaključak za ispit:
Promjena URL-a u fetch:

Promijeni URL zavisno od toga šta ti treba: /customers, /products, /customer/meals/${id}, itd.

Ako koristiš query parametre (npr. za paginaciju), dodaj ih ?offset=0&limit=10 u URL.

Dinamicki URL:

Ako trebaš ID korisnika ili proizvoda u URL-u, koristiš ${id} da napraviš dinamički URL.

POST, PUT, DELETE:

Za POST pošalješ podatke u body kao JSON.

Za PUT i DELETE koristiš odgovarajuće metode (PUT, DELETE).



