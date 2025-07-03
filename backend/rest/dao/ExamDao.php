<?php

class ExamDao {
    private $conn;

    public function __construct() {
        try {
            $host="localhost";
            $db="webfinal";
            $user="root";
            $pass="";
            $port=3306;

            $this->conn= new PDO("mysql:host=$host;port=$port;dbname=$db",$user,$pass);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

        } catch (PDOException $e) {
            echo "Connection failed: " . $e->getMessage();
        }
    }

        
    public function get_customers() {
        // TODO
        $stmt=$this->conn->query("SELECT * FROM customers");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function get_customer_meals($customer_id) {
        // TODO
        $stmt=$this->conn->prepare("SELECT f.id,f.brand,m.customer_id
        FROM meals m
        join foods f
        where m.customer_id=?");
        $stmt->execute([$customer_id]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function add_customer($data) {
        // TODO
        $stmt=$this->conn->prepare("INSERT INTO customers(first_name,last_name,birth_date,status)
        VALUES (:first_name,:last_name,:birth_date,:status)");
        $stmt->execute([
            ":first_name"=>$data["first_name"],
            ":last_name"=>$data["last_name"],
            ":birth_date"=>$data["birth_date"],
            ":status"=>$data["status"]
        ]);
        return $this->conn->lastInsertId();
    }

    public function get_foods_report() {
        // TODO
        $stmt=$this->conn->query('SELECT * FROM foods f');
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }


        //DODATNO -> UPDATE

    public function update_customer($id, $data) {
        $stmt = $this->conn->prepare("
            UPDATE customers 
            SET first_name = :first_name, 
                last_name = :last_name, 
                birth_date = :birth_date, 
                status = :status 
            WHERE id = ?
        ");
        $stmt->execute([
            ":first_name" => $data["first_name"], 
            ":last_name" => $data["last_name"], 
            ":birth_date" => $data["birth_date"], 
            ":status" => $data["status"],
            $id  // koristi $id za WHERE id = ?
        ]);
        return $stmt->rowCount();
    }


    //DELETE

    public function delete_customer($customer_id) {
        // Upit s ? kao placeholder
        $stmt = $this->conn->prepare("DELETE FROM customers WHERE id = ?");
        
        // Izvršavanje upita s parametrom
        $stmt->execute([$customer_id]);
        
        // Vraća broj obrisanih redova
        return $stmt->rowCount();
    }


}

?>
