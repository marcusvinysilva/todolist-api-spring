package br.com.marcussilva.todolist.task;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.marcussilva.todolist.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/tasks")
public class TaskController {

  @Autowired
  private ITaskRepository taskRepository;

  @PostMapping("/")
  public ResponseEntity create(@RequestBody TaskModel taskModel, HttpServletRequest request) {
    UUID idUser = (UUID) request.getAttribute("idUser");
    taskModel.setIdUser(idUser);

    LocalDateTime currentDate = LocalDateTime.now();
    if (currentDate.isAfter(taskModel.getStartAt()))
      return ResponseEntity.status(HttpStatus.OK).body("A data de início deve ser maior que a data atual");

    if (currentDate.isAfter(taskModel.getEndAt()))
      return ResponseEntity.status(HttpStatus.OK).body("A data de término deve ser maior que a data atual");

    if (taskModel.getStartAt().isAfter(taskModel.getEndAt()))
      return ResponseEntity.status(HttpStatus.OK).body("A data de início deve ser menor do que a data de término");

    TaskModel task = this.taskRepository.save(taskModel);
    return ResponseEntity.status(HttpStatus.CREATED).body(task);
  }

  @GetMapping("/")
  public List<TaskModel> list(HttpServletRequest request) {
    UUID idUser = (UUID) request.getAttribute("idUser");
    List<TaskModel> tasks = this.taskRepository.findByIdUser(idUser);
    return tasks;
  }

  @PatchMapping("/{id}")
  public ResponseEntity update(@RequestBody TaskModel taskModel, @PathVariable UUID id, HttpServletRequest request) {
    TaskModel task = this.taskRepository.findById(id).orElse(null);
    if (task == null)
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Tarefa não encontrada");

    UUID idUser = (UUID) request.getAttribute("idUser");
    if (!task.getIdUser().equals(idUser))
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuário não tem permissão para alterar essa tarefa");

    Utils.copyNonNullProperties(taskModel, task);

    TaskModel taskUpdated = this.taskRepository.save(task);
    return ResponseEntity.ok().body(taskUpdated);
  }

}
