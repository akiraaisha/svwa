delete_post = function(id) {
    $.post($SCRIPT_ROOT + 'post/delete/' + id, function(data) {
        if (data.delete){
            $('.post#' + id).remove();
        } else {
            flash("Unable to delete thread " + id);
        }
    });
};
