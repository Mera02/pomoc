<?php
require_once __DIR__ . '/../services/ExamService.php';
require_once __DIR__ . '/../middleware/Middleware.php';

Flight::route('GET /connection-check', function() {
    // TODO: test konekcije
    new ExamDao();
});

Flight::route('GET /customers', function() {
    // TODO: pozvati service i vratiti JSON
    $service=new ExamService();
    Flight::json($service->get_customers());
});

Flight::route('GET /customer/meals/@customer_id', function($customer_id) {
    // TODO
    $service=new ExamService();
    Flight::json($service->get_customer_meals($customer_id));
});

Flight::route('POST /customers/add', function() {
    Middleware::check_auth();
    // TODO
    $data=Flight::request()->data->getData();
    $service=new ExamService();
    $new_id=$service->add_customer($data);
    $data['id']=$new_id;
    Flight::json($data);
});

Flight::route('GET /foods/report', function() {
    // TODO
    $service=new ExamService();
    Flight::json($service->get_foods_report());
});


//UPDATE

Flight::route('PUT /customers/update/@id', function($id){
    $data = Flight::request()->data->getData();
    $service = new ExamService();
    Flight::json($service->update_customer($id, $data)); // odmah vraća JSON
});



//DELETE

Flight::route('DELETE /customers/delete/@id', function($id){
    $service = new ExamService();
    Flight::json($service->delete_customer($id)); // odmah vraća JSON
});



?>
